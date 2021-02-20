use std::fs::read_to_string;
use std::time::Instant;
use uows_crypto::Data;

#[test]
fn verify() {
    let t = Instant::now();
    let x = read_to_string("tests/key").unwrap();
    println!("{}", x);

    let karr: Vec<&str> = x.split('\n').map(|s| s).collect();

    let enc = Data::new(karr[0], karr[1]);

    let denc = enc.parse_enc("Hello, World!", true).unwrap_to_num_string();

    println!("{}", denc);

    let den2 = enc
        .parse_enc_wkey("Hello, World!", true)
        .1
        .unwrap_to_num_string();

    println!("{}", den2);

    let dec1 = enc
        .parse_dec(den2.as_ref(), false)
        .unwrap_to_string_from_dat()
        .unwrap();

    println!("{}", dec1);

    assert_eq!("166 239 3 233 31 185 201 196 85 187 123 48 31 51 219 199 126 67 229 108 10 128 82 163 87 14 144 144 52".to_string(), denc);
    assert_eq!("166 239 3 233 31 185 201 196 85 187 123 48 31 51 219 199 126 67 229 108 10 128 82 163 87 14 144 144 52".to_string(), den2);
    assert_eq!("Hello, World!".to_string(), dec1);

    println!("{:?}", t.elapsed())
}
