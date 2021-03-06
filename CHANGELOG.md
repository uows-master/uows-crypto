# 0.1.0

# 0.1.1
## Major Changes
* Added methods on `Cipher` enum
* Added method `init` on `Data` struct, taking key and nonce from stdin

# 0.1.2
## Minor Bugfix
* Added spacing to `Cipher::unwrap_to_num_string`

# 0.1.3
## Major Bugfix
* `Data::decrypt` function was calling the `encrypt` backend

# 0.1.4
## Minor Change
* Licence changed to GNU AGPL-3.0

# 0.1.5
## Minor Change
* Derived `Clone` for `Cipher` enum

# 0.2.0
## Breaking Change
* Removed `Data::decrypt_to_string`
## Major Changes
* Massive performance improvements (refer to commits)
* Added `Data::new_from_bytes` to initialise from `Vec<u8>` instead of `&str`

# 0.2.1
## Minor Bugfix
* Fixed nonce length error message