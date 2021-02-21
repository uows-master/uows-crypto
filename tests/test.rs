use std::fs::{read, read_to_string};
use std::time::Instant;
use uows_crypto::Data;

#[test]
fn verify() {
    let t = Instant::now();
    let x = read_to_string("tests/key").unwrap();
    println!("File: {}", x);

    let karr: Vec<&str> = x.split('\n').map(|s| s).collect();

    let enc = Data::new(karr[0], karr[1]);

    let denc = enc.parse_enc("Hello, World!", true).unwrap_to_num_string();

    println!("Str: {}", denc);

    let den2 = enc
        .parse_enc_wkey("Hello, World!", true)
        .1
        .unwrap_to_num_string();

    println!("Str: {}", den2);

    let dec1 = enc
        .parse_dec(den2.as_ref(), false)
        .unwrap_to_string_from_dat()
        .unwrap();

    println!("Str: {}", dec1);

    println!("Str: {:?}", t.elapsed());

    assert_eq!("166 239 3 233 31 185 201 196 85 187 123 48 31 51 219 199 126 67 229 108 10 128 82 163 87 14 144 144 52".to_string(), denc);
    assert_eq!("166 239 3 233 31 185 201 196 85 187 123 48 31 51 219 199 126 67 229 108 10 128 82 163 87 14 144 144 52".to_string(), den2);
    assert_eq!("Hello, World!".to_string(), dec1);
}

#[test]
fn verify_bytes() {
    let t = Instant::now();
    let x = read("tests/key").unwrap();
    // println!("{}", x);

    let karr = x.split_at(33);

    let enc = Data::new_from_bytes(
        {
            let mut k = karr.0.to_vec();
            k.pop();
            k
        },
        karr.1.to_vec(),
    );

    let et = Instant::now();

    let denc = enc.parse_enc("Hello, World!", true).unwrap_to_num_string();

    println!("Bytes ETime: {:?}", et.elapsed());

    println!("Bytes: {}", denc);

    let ekt = Instant::now();

    let den2 = enc
        .parse_enc_wkey("Hello, World!", true)
        .1
        .unwrap_to_num_string();

    println!("Bytes EKTime: {:?}", ekt.elapsed());

    println!("Bytes: {}", den2);

    let dt = Instant::now();

    let dec1 = enc
        .parse_dec(den2.as_ref(), false)
        .unwrap_to_string_from_dat()
        .unwrap();

    println!("Bytes Dtime: {:?}", dt.elapsed());

    println!("Bytes: {}", dec1);

    println!("Bytes: {:?}", t.elapsed());

    assert_eq!("166 239 3 233 31 185 201 196 85 187 123 48 31 51 219 199 126 67 229 108 10 128 82 163 87 14 144 144 52".to_string(), denc);
    assert_eq!("166 239 3 233 31 185 201 196 85 187 123 48 31 51 219 199 126 67 229 108 10 128 82 163 87 14 144 144 52".to_string(), den2);
    assert_eq!("Hello, World!".to_string(), dec1)
}
