use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;

#[derive(Clone)]
pub enum Cipher {
    Key(Vec<u8>),
    Data(Vec<u8>),
}

impl Cipher {
    pub fn unwrap_key(self) -> Result<Vec<u8>, String> {
        match self {
            Cipher::Key(k) => Ok(k),
            Cipher::Data(_) => Err("This is data, not a key".to_string()),
        }
    }

    pub fn unwrap_data(self) -> Result<Vec<u8>, String> {
        match self {
            Cipher::Data(d) => Ok(d),
            Cipher::Key(_) => Err("This is a key, not data".to_string()),
        }
    }

    /// Do NOT call this unless absolutely sure about the enum type.
    /// Call [`unwrap_key`] or [`unwrap_data`] instead.
    pub fn unwrap(self) -> Vec<u8> {
        match self {
            Cipher::Key(k) => k,
            Cipher::Data(d) => d,
        }
    }

    pub fn unwrap_to_num_string(self) -> String {
        let mut x: String;

        match self {
            Cipher::Key(k) => {
                x = k.iter().map(|i| i.to_string() + " ").collect();
                x.pop();
            }
            Cipher::Data(d) => {
                x = d.iter().map(|i| i.to_string() + " ").collect();
                x.pop();
            }
        };

        x
    }

    /// Only call this function when you are sure that the enum contains
    /// decrypted data and is [`Cipher::Data`]
    pub fn unwrap_to_string_from_dat(self) -> Result<String, String> {
        let mut x = String::new();
        let mut y: Result<String, String> = Ok("".to_string());

        match self {
            Cipher::Data(k) => x = k.iter().map(|i| *i as char).collect(),
            Cipher::Key(_) => y = Err("Not Data".to_string()),
        };

        match y {
            Ok(_) => Ok(x),
            Err(_) => y,
        }
    }
}

pub struct Data {
    key: Vec<u8>,
    nonce: Vec<u8>,
    enc: Aes256Gcm,
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

        Data {
            key: key.as_bytes().to_vec(),
            nonce: nonce.as_bytes().to_vec(),
            enc: Aes256Gcm::new(GenericArray::from_slice(key.as_bytes())),
        }
    }

    pub fn new_from_bytes(key: Vec<u8>, nonce: Vec<u8>) -> Data {
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

        Data {
            key: key.clone(),
            nonce,
            enc: Aes256Gcm::new(GenericArray::from_slice(key.as_slice())),
        }
    }

    /// Check key and data using [`Cipher`] enum and match
    pub fn encrypt_wkey(&self, data: Vec<u8>) -> (Cipher, Cipher) {
        let non = GenericArray::from_slice(self.nonce.as_slice());

        let ciphertext = self
            .enc
            .encrypt(non, data.as_ref())
            .expect("Encryption of data failed");

        let cipherkey = self
            .enc
            .encrypt(non, self.key.as_ref())
            .expect("Encryption of key failed");

        (Cipher::Key(cipherkey), Cipher::Data(ciphertext))
    }

    /// Does not return the encrypted [`Cipher::Key`]
    pub fn encrypt(&self, data: Vec<u8>) -> Cipher {
        let non = GenericArray::from_slice(self.nonce.as_slice());

        let ciphertext = self
            .enc
            .encrypt(non, data.as_ref())
            .expect("Encryption of data failed");

        Cipher::Data(ciphertext)
    }

    /// Returns decrypted plaintext as [`Cipher::Data`]
    pub fn decrypt(&self, data: Vec<u8>) -> Cipher {
        let non = GenericArray::from_slice(self.nonce.as_slice());

        let plaintext = self
            .enc
            .decrypt(non, data.as_ref())
            .expect("Encryption of data failed");

        Cipher::Data(plaintext)
    }

    /// Directly encrypts data from [`&str`], returns key and data
    pub fn parse_enc_wkey(&self, s: &str, is_str: bool) -> (Cipher, Cipher) {
        let tmp;
        if is_str {
            tmp = s.as_bytes().iter().map(|x| *x).collect();
        } else {
            tmp = s.split(' ').map(|s| s.parse::<u8>().unwrap()).collect();
        }

        self.encrypt_wkey(tmp)
    }

    /// Directly encrypts data from [`&str`], returns data only
    pub fn parse_enc(&self, s: &str, is_str: bool) -> Cipher {
        let tmp;
        if is_str {
            tmp = s.as_bytes().iter().map(|x| *x).collect();
        } else {
            tmp = s.split(' ').map(|s| s.parse::<u8>().unwrap()).collect();
        }

        self.encrypt(tmp)
    }

    /// Direct decryption from [`&str`]
    pub fn parse_dec(&self, s: &str, is_str: bool) -> Cipher {
        let tmp;
        if is_str {
            tmp = s.as_bytes().iter().map(|x| *x).collect();
        } else {
            tmp = s.split(' ').map(|s| s.parse::<u8>().unwrap()).collect();
        }

        self.decrypt(tmp)
    }
}
