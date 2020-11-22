# Cryptopals solutions in Rust

## Set 1

### Challenge 1

```
$ cargo run --bin hex <hex string>
```

### Challenge 2

```
$ cargo run --bin xor <hex string 1> <hex string 2>
```

### Challenge 3
```
$ cargo run --bin xor_search_single_char <hex string>
```

### Challenge 4

```
$ cargo run --bin find_single_single_char_xor_string resources/set1/4.txt
```

### Challenge 5

```
$ cargo run --bin --bin encrypt_xor resources/set1/5.txt ICE
```

### Challenge 6

```
$ cargo run --bin break_repeating_key_xor resources/set1/6.txt
```

### Challenge 7

```
$ cargo run --bin aes_ecb resources/set1/7.txt "YELLOW SUBMARINE"
```

### Challenge 8

```
$ cargo run --bin find_aes_ecb resources/set1/8.txt
```

## Set 2

### Challenge 9

TBD 

### Challenge 10

```
$ cargo run --bin aes_cbc resources/set2/10.txt "YELLOW SUBMARINE"
```

### Challenge 11

```
$ cargo run --bin oracle_ecb AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

### Challenge 12

```
$ cargo run --bin ecb_byte_at_a_time simple
```

### Challenge 13

Generate a key
```
$ cargo run --bin gen_key
```

```
$ cargo run --bin ecb_cut_n_paste cut-n-paste <key>
```

### Challenge 14

```
$ cargo run --bin ecb_byte_at_a_time harder
```

### Challenge 16
```
$ cargo run --bin cbc_bitflip "aaaaaaaaaaaaaaaaaaaaa:admin<true"
```
