<div align="center">

  <h1><code>anon-sym-ake</code></h1>

  <strong>Implementation of `anon-sym-ake`</strong>

  [![ci](https://github.com/jiep/anon-sym-ake/actions/workflows/rust.yml/badge.svg)](https://github.com/jiep/anon-sym-ake/actions/workflows/rust.yml)
  [![dependency status](https://deps.rs/repo/github/jiep/anon-sym-ake/status.svg)](https://deps.rs/repo/github/jiep/anon-sym-ake)

  <sub>Built with 🦀</sub>
</div>

## Dependencies

* [`liboqs`](https://github.com/open-quantum-safe/liboqs-rust): for Post-Quantum KEM
* [`lb-vrf`](https://github.com/zhenfeizhang/lb-vrf): for Lattices-Based VRF

## Protocol

```mermaid
sequenceDiagram
participant Client i
participant Server
Client i -->> Server: Request for registration
Note right of Server: Registration<br/>(ek_i, vk_i) <- VRF.Gen(λ)
Server ->> Client i: ek_i
Note left of Client i: Round 1<br />n_i <-$ R<br />(comm_i, open_i) <- COMM.Comm(n_i)
Client i -->> Server: m_1 := (comm_i)
Note right of Server: Round 2<br />(pk*, sk*) <- PKE.Gen(λ)<br />n_S, r <-$ R<br />Do for all i ∈ C := {1,...,l}:<br />(y_i, π_i) <- VRF.Eval(ek_i, r)<br />c_i := y_i ⊕ n_S <br />End Do<br />
Server ->> Client i: m_2 := (c_1, ..., c_l, r, pk*)
Note left of Client i: Round 3<br />n_S := VRF.Eval(ek_i, r) ⊕ c_i<br/>(comm_S, open_S) <- COMM.Comm(n_S) 
Client i -->> Server: m_3 := (comm_S)
Server ->> Client i: m_4 := (π_1, ..., π_l)
Note left of Client i: Round 5<br/>Do for all j in C\{i}<br/>Assert VRF.Vry(vk_j, r, n_S ⊕ c_j, π_j) == 1<br/>End Do<br/> K := n_S ⊕ n_i<br/>ctx_i := PKE.Enc(pk*, open_i)
Client i -->> Server: m_5 := (ctx_i, open_S)
Note right of Server: Round 6<br />open_i := PKE.Dec(sk*, ctx_i)<br/>Assert Comm.Vfy(comm_i, open_i) == 1<br/>Assert Comm.Vfy(comm_S, open_S) == 1<br/>K := n_S ⊕ n_i
```

## Supported algorithms
  
    * Kyber512
    * Kyber512_90s
    * Kyber768
    * Kyber768_90s
    * Kyber1024
    * Kyber1024_90s

## Binaries

Download the latest version from [Releases](https://github.com/jiep/anon-sym-ake/releases).

## Build from source

1. Install [Rust](https://www.rust-lang.org/tools/install)
2. Check source code

```
cargo check
``` 

3. Compile binary

```
cargo build
``` 

4. Run tests

```
cargo test
```

> Note: for release target, add --release

5. Run binary

```
cargo run
# or
./target/release/anon-sym-ake # for release version
./target/debug/anon-sym-ake # for debug version
```

## 🚴 Usage

```
./target/debug/anon-sym-ake --help
Usage: anon-sym-ake [OPTIONS] --kem <KEM> --clients <CLIENTS>

Options:
  -k, --kem <KEM>          
  -c, --clients <CLIENTS>  
  -v, --verbose            
  -h, --help               Print help information
  -V, --version            Print version information
```

### Example

10 clients (the protocol is executed with just one!) with Kyber1024 as KEM

```
./target/release/anon-sym-ake --kem Kyber1024 --clients 10 --verbose
[!] Generating param and seed for PQ VRF...
[!] Setting Kyber1024 as KEM...

[!] Creating 10 clients...
[!] Creating server...

[R] Creating (ek, vk) for 10 clients...

[!] Time elapsed in registration of 10 clients is 5.890227ms

[!] Starting protocol with client0 and server...

[C] Running Round 1...
[!] Time elapsed in Round 1 is 5.2µs
[C -> S] Sending m1 to server...

[S] Running Round 2...
[!] Time elapsed in Round 2 is 84.785926ms
[C <- S] Sending m2 to client0...

[C] Running Round 3...
[!] Time elapsed in Round 3 is 8.876892ms
[C -> S] Sending m3 to server...

[S] Running Round 4...
[!] Time elapsed in Round 4 is 136.503µs
[C <- S] Sending m4 to client...

[C] Running Round 5...
[C] VRF verification for j=0 -> OK
[C] VRF verification for j=1 -> OK
[C] VRF verification for j=2 -> OK
[C] VRF verification for j=3 -> OK
[C] VRF verification for j=4 -> OK
[C] VRF verification for j=5 -> OK
[C] VRF verification for j=6 -> OK
[C] VRF verification for j=7 -> OK
[C] VRF verification for j=8 -> OK
[C] VRF verification for j=9 -> OK
[!] Time elapsed in Round 5 is 24.049718ms
[C -> S] Sending m5 to server...

[S] Running Round 6...
[S] Commitment verification -> OK
[!] Time elapsed in Round 6 is 41.501µs

[!] Printing session keys...
[C] 0x8ceec8fa1175d310e53a78727bbdb97fb07863994531d8e95df5975c6232523f
[S] 0x8ceec8fa1175d310e53a78727bbdb97fb07863994531d8e95df5975c6232523f
[!] Printing diagram...

                 Client i                     Server
                    |                            |
                    |                            | <---    Registration 
                    |                            |         for 10 clients
                    |                            |         (005 ms)
Round 1        ---> |                            |
(00000005 µs)       |                            |
                    |                            |
                    |-------------m1------------>|
                    |        (0000032 B)         |
                    |                            | <---    Round 2
                    |                            |         (00000084 ms)
                    |                            |
                    |<------------m2-------------|
                    |        (0002480 B)         |
Round 3        ---> |                            |
(00000008 ms)       |                            |
                    |                            |
                    |-------------m3------------>|
                    |        (0000032 B)         |   
                    |                            | <---    Round 4
                    |                            |         (00000000 ms)
                    |                            |
                    |<------------m4-------------|
                    |        (0011050 B)         |
Round 5        ---> |                            |
(00000024 ms)       |                            |
                    |                            |
                    |-------------m5------------>|
                    |        (0001836 B)         |   
                    |                            | <---    Round 6
                    |                            |         (00000041 µs)
                    |                            |
```