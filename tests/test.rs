use std::fs::read_to_string;
use uows_crypto::Data;

#[test]
fn verify() {
    let x = read_to_string("tests/key").unwrap();
    println!("{}", x);

    let karr: Vec<&str> = x.split('\n').map(|s| s).collect();

    let enc = Data::new(karr[0], karr[1]);

    let denc = enc
        .encrypt("Hello, World!".as_bytes().to_vec())
        .unwrap_to_num_string();

    println!("{}", denc);

    assert_eq!("166 239 3 233 31 185 201 196 85 187 123 48 31 51 219 199 126 67 229 108 10 128 82 163 87 14 144 144 52".to_string(), denc)
}
