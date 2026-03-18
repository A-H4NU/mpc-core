use std::io;
use std::num::NonZero;

use chacha20poly1305::aead::generic_array::{GenericArray, typenum::Unsigned};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit};
use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

pub struct SecureStream<S: AsyncRead + AsyncWrite + Unpin> {
    inner: S,
    cipher: ChaCha20Poly1305,
    send_counter: u64,
    recv_counter: u64,
    role: ConnectionRole,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ConnectionRole {
    Listener,
    Initiator,
}

const U32_LEN: usize = u32::BITS as usize / 8;
const TAG_LEN: usize = <ChaCha20Poly1305 as chacha20poly1305::AeadCore>::TagSize::USIZE;

impl<S: AsyncRead + AsyncWrite + Unpin> SecureStream<S> {
    pub fn new(stream: S, shared_secret: &[u8; 32], role: ConnectionRole) -> Self {
        let key = Key::from_slice(shared_secret);
        let cipher = ChaCha20Poly1305::new(key);
        Self {
            inner: stream,
            cipher,
            send_counter: 0,
            recv_counter: 0,
            role,
        }
    }

    pub async fn send(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.send_counter.to_be_bytes());
        if self.role == ConnectionRole::Listener {
            nonce_bytes[0] = 1_u8;
        }
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let total_len = data.len() + TAG_LEN;
        let total_len_bytes = (total_len as u32).to_be_bytes();

        let mut buffer = data.to_vec();
        self.cipher
            .encrypt_in_place(nonce, &total_len_bytes, &mut buffer)
            .map_err(|_| io::Error::other("Encryption error"))?;

        debug_assert!(buffer.len() == total_len);

        self.inner.write_all(&total_len_bytes).await?;
        self.inner.write_all(&buffer).await?;

        self.send_counter += 1;
        Ok(U32_LEN + total_len)
    }

    pub async fn recv(&mut self) -> io::Result<(Vec<u8>, usize)> {
        let mut len_buf = [0u8; U32_LEN];

        self.inner.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        if total_len < TAG_LEN {
            return Err(io::Error::other("Packet too short"));
        }

        let mut buffer = vec![0u8; total_len];
        self.inner.read_exact(&mut buffer).await?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.recv_counter.to_be_bytes());
        if self.role == ConnectionRole::Initiator {
            nonce_bytes[0] = 1_u8;
        }
        let nonce = GenericArray::from_slice(&nonce_bytes);

        self.cipher
            .decrypt_in_place(nonce, &len_buf, &mut buffer)
            .map_err(|_| io::Error::other("Decryption error"))?;

        self.recv_counter += 1;
        Ok((buffer, U32_LEN + total_len))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecureStream<S> {
    pub async fn send_object<T>(&mut self, obj: &T) -> io::Result<usize>
    where
        T: Serialize,
    {
        self.send_objects(core::slice::from_ref(obj)).await
    }

    pub async fn send_objects<T>(&mut self, objs: &[T]) -> io::Result<usize>
    where
        T: Serialize,
    {
        let data =
            postcard::to_stdvec(objs).map_err(|_| io::Error::other("Serialization error"))?;
        self.send(&data).await
    }

    pub async fn recv_object<T>(&mut self) -> io::Result<(T, usize)>
    where
        T: for<'de> Deserialize<'de>,
    {
        let (vec, received_bytes) = self
            .recv_objects(Some(NonZero::<usize>::new(1).unwrap()))
            .await?;
        Ok((vec.into_iter().next().unwrap(), received_bytes))
    }

    pub async fn recv_objects<T>(
        &mut self,
        count: Option<NonZero<usize>>,
    ) -> io::Result<(Vec<T>, usize)>
    where
        T: for<'de> Deserialize<'de>,
    {
        let (data, received_bytes) = self.recv().await?;
        let objects: Vec<T> = postcard::from_bytes(&data)
            .map_err(|e| io::Error::other(format!("Deserialization error: {}", e)))?;
        if let Some(count) = count
            && objects.len() != count.into()
        {
            return Err(io::Error::other(format!(
                "Count mismatch: received {} objects, expected {}",
                objects.len(),
                count
            )));
        }
        Ok((objects, received_bytes))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecureStream<S> {
    pub async fn perform_handshake(
        mut stream: S,
        my_identity: &SigningKey,
        peer_identity: &VerifyingKey,
        role: ConnectionRole,
    ) -> io::Result<SecureStream<S>> {
        // 1. Generate Ephemeral (Session) Keys (X25519)
        let my_secret = EphemeralSecret::random_from_rng(chacha20poly1305::aead::OsRng);
        let my_public = XPublicKey::from(&my_secret);

        // 2. Send My Ephemeral Public Key
        let my_pub_bytes = my_public.as_bytes();
        stream.write_all(my_public.as_bytes()).await?;

        // 3. Receive Peer's Ephemeral Public Key
        let mut peer_pub_bytes = [0u8; PUBLIC_KEY_LENGTH];
        stream.read_exact(&mut peer_pub_bytes).await?;
        let peer_public = XPublicKey::from(peer_pub_bytes);

        // 4. Compute Shared Session Key (ECDH)
        let shared_secret = my_secret.diffie_hellman(&peer_public);
        let session_key_bytes = shared_secret.to_bytes();

        // 5. Authentication Phase (Prevent Man-in-the-Middle)
        let mut signature_payload = Vec::with_capacity(PUBLIC_KEY_LENGTH * 2);
        signature_payload.extend_from_slice(my_pub_bytes);
        signature_payload.extend_from_slice(&peer_pub_bytes);

        let signature = my_identity.sign(&signature_payload);
        stream.write_all(&signature.to_bytes()).await?;

        let mut peer_sig_bytes = [0u8; SIGNATURE_LENGTH];
        stream.read_exact(&mut peer_sig_bytes).await?;
        let peer_signature = Signature::from_bytes(&peer_sig_bytes);

        // 6. Verify Peer
        let mut peer_payload = Vec::with_capacity(PUBLIC_KEY_LENGTH * 2);
        peer_payload.extend_from_slice(&peer_pub_bytes);
        peer_payload.extend_from_slice(my_pub_bytes);

        peer_identity
            .verify(&peer_payload, &peer_signature)
            .map_err(|_| io::Error::other("Authentication failed: Invalid Signature"))?;

        // 7. Upgrade to SecureStream
        Ok(SecureStream::new(stream, &session_key_bytes, role))
    }
}
