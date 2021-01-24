use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;

pub enum Cipher {
    Key(Vec<u8>),
    Data(Vec<u8>),
}

pub struct Data {
    key: String,
    nonce: String,
}

impl Data {
    /// `key` should be 32 chars long. `nonce` should be 12 chars long.
    pub fn new(key: &str, nonce: &str) -> Data {
        if key.len() != 32 {
            panic!(format!(
                "Key isn't 32 chars long. It is {} chars long.",
                key.len()
            ))
        }

        if nonce.len() != 12 {
            panic!(format!(
                "Nonce isn't 12 chars long. It is {} chars long.",
                key.len()
            ))
        }

        let tmp = Data {
            key: key.to_string(),
            nonce: nonce.to_string(),
        };

        tmp
    }

    /// Check key and data using [`Cipher`] enum and match
    pub fn encrypt_wkey(&self, data: Vec<u8>) -> (Cipher, Cipher) {
        let key = GenericArray::from_slice(self.key.as_bytes());
        let enc = Aes256Gcm::new(key);

        let non = GenericArray::from_slice(self.nonce.as_bytes());

        let ciphertext = enc
            .encrypt(non, data.as_ref())
            .expect("Encryption of data failed");

        let cipherkey = enc
            .encrypt(non, self.key.as_ref())
            .expect("Encryption of key failed");

        (Cipher::Key(cipherkey), Cipher::Data(ciphertext))
    }

    /// Check key and data using [`Cipher`] enum and match
    pub fn encrypt(&self, data: Vec<u8>) -> Cipher {
        let key = GenericArray::from_slice(self.key.as_bytes());
        let enc = Aes256Gcm::new(key);

        let non = GenericArray::from_slice(self.nonce.as_bytes());

        let ciphertext = enc
            .encrypt(non, data.as_ref())
            .expect("Encryption of data failed");

        Cipher::Data(ciphertext)
    }

    /// data should be [`Vec<u8>`]
    pub fn decrypt(&self, data: Vec<u8>) -> Cipher {
        let key = GenericArray::from_slice(self.key.as_bytes());
        let enc = Aes256Gcm::new(key);

        let non = GenericArray::from_slice(self.nonce.as_bytes());

        let plaintext = enc
            .encrypt(non, data.as_ref())
            .expect("Encryption of data failed");

        Cipher::Data(plaintext)
    }

    /// Direct decryption to string
    pub fn decrypt_to_string(&self, data: Vec<u8>) -> String {
        let key = GenericArray::from_slice(self.key.as_bytes());
        let enc = Aes256Gcm::new(key);

        let non = GenericArray::from_slice(self.nonce.as_bytes());

        let plaintext = enc
            .encrypt(non, data.as_ref())
            .expect("Encryption of data failed");

        let mut out = String::new();

        for i in plaintext {
            out.push(i as char);
        }

        out
    }

    /// Directly encrypts data from string, returns key and data
    pub fn parse_enc_wkey(&self, s: &str, is_str: bool) -> (Cipher, Cipher) {
        let mut tmp: Vec<u8> = Vec::new();
        if is_str {
            for i in s.as_bytes().iter() {
                tmp.push(*i)
            }
        } else {
            tmp = s.split(' ').map(|s| s.parse::<u8>().unwrap()).collect();
        }

        self.encrypt_wkey(tmp)
    }

    /// Directly encrypts data from [`&str`] OR [`Vec<u8>`], returns data only
    pub fn parse_enc(&self, s: &str, is_str: bool) -> Cipher {
        let mut tmp: Vec<u8> = Vec::new();
        if is_str {
            for i in s.as_bytes().iter() {
                tmp.push(*i)
            }
        } else {
            tmp = s.split(' ').map(|s| s.parse::<u8>().unwrap()).collect();
        }

        self.encrypt(tmp)
    }
}