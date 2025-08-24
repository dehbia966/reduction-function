# Hellman TMTO in Rust

This is a small **2-day project** I developed during my vacation to keep my skills sharp in **Rust** and **Cryptography**.  
It implements a basic **Hellman Time-Memory Trade-Off (TMTO) table** with a custom reduction function.

##  Features
- Implementation of a **reduction function** across tables and rounds  
- Handling of **little-endian bit extraction** (38 least significant bits)  
- Use of **bit rotations** to improve distribution  
- Integration of **ChaCha RNG (chacharng20)** for randomness  

##  Project structure
- `src/main-dehbia.rs` → main implementation (reduction, rotations, domain mapping)  
- `Cargo.toml` → Rust dependencies and metadata  

##  How to run
Make sure you have [Rust](https://www.rust-lang.org/) installed.

```bash
# Build
cargo build --release

# Run (example)
cargo run
