<div align="center">

  <h1><code>anon-sym-ake</code></h1>

  <strong>Implementation of `anon-sym-ake`</strong>

  <p>
    <a href="https://github.com/jiep/anon-sym-ake/actions"><img src="https://github.com/jiep/anon-sym-ake/actions/workflows/rust.yml/badge.svg" alt="Build Status" /></a>
  </p>

  <sub>Built with 🦀</sub>
</div>

## Dependencies

* [`liboqs`](https://github.com/open-quantum-safe/liboqs-rust): for Post-Quantum KEM and signatures
* [`lb-vrf`](https://github.com/zhenfeizhang/lb-vrf): for Lattices-Based VRF

## Protocol

```
sequenceDiagram
participant Client i
participant Server
Note right of Server: Init<br/>(pk_S, sk_S) <- SIG.Gen(λ)
Client i -->> Server: Request for registration
Note right of Server: Registration<br/>(ek_i, vk_i) <- VRF.Gen(λ)
Server ->> Client i: ek_i
Note left of Client i: Round 1<br />n_i <-$ R<br />(comm, open) <- COMM.Comm(n_i)
Client i -->> Server: m_1 := ("init comm)
Note right of Server: Round 2<br />(pk*, sk*) <- PKE.Gen(λ)<br />n_S, r <-$ R<br />Do for all i ∈ C := {1,...,l}:<br />(y_i, π_i) <- VRF.Eval(ek_i, r)<br />c_i := y_i ⊕ n_S <br />End Do<br />m := (c_1, ..., c_l, π_1, ..., π_l, r, pk*)<br/>σ := SIG.Sign(sk_S, m)
Server ->> Client i: m2 := (σ, m)
Note left of Client i: Round 3<br />Assert SIG.Vfy(pk_S, σ, m_2) == 1<br />n_S := VRF.Eval(ek_i, r) ⊕ c_i<br/>Do for all j in C\{i}<br/>Assert VRF.Vry(vk_j, r, n_S) ⊕ c_j, π_j) == 1<br/>End Do<br/> K := n_S ⊕ n_i<br/>cn_i := PKE.Enc(pk*, n_i) 
Client i -->> Server: m_3 := (open, cn_i)
Note right of Server: Round 4<br />Assert Comm.Vfy(comm, open) == 1<br />n_i := PKE.Dec(sk*, cn_i)<br/>Do for all j in C\{i}<br/>Assert VRF.Vry(vk_j, r, n_S) ⊕ c_j, π_j) == 1<br/> K := n_S ⊕ n_i<br/>cn_i := PKE.Enc(pk*, n_i)<br/>K := n_S ⊕ n_i
```

## Supported algorithms

<details>
  <summary>Click to expand supported KEMs!</summary>
    * Kyber512
    * Kyber512_90s
    * Kyber768
    * Kyber768_90s
    * Kyber1024
    * Kyber1024_90s
</details>

<details>
  <summary>Click to expand supported Signature schemes!</summary>
    * SphincsHaraka128fRobust
    * SphincsHaraka128fSimple
    * SphincsHaraka128sRobust
    * SphincsHaraka128sSimple
    * SphincsHaraka192fRobust
    * SphincsHaraka192fSimple
    * SphincsHaraka192sRobust
    * SphincsHaraka192sSimple
    * SphincsHaraka256fRobust
    * SphincsHaraka256fSimple
    * SphincsHaraka256sRobust
    * SphincsHaraka256sSimple
    * SphincsSha256128fRobust
    * SphincsSha256128fSimple
    * SphincsSha256128sRobust
    * SphincsSha256128sSimple
    * SphincsSha256192fRobust
    * SphincsSha256192fSimple
    * SphincsSha256192sRobust
    * SphincsSha256192sSimple
    * SphincsSha256256fRobust
    * SphincsSha256256fSimple
    * SphincsSha256256sRobust
    * SphincsSha256256sSimple
    * SphincsShake256128fRobust
    * SphincsShake256128fSimple
    * SphincsShake256128sRobust
    * SphincsShake256128sSimple
    * SphincsShake256192fRobust
    * SphincsShake256192fSimple
    * SphincsShake256192sRobust
    * SphincsShake256192sSimple
    * SphincsShake256256fRobust
    * SphincsShake256256fSimple
    * SphincsShake256256sRobust
    * SphincsShake256256sSimple
</details>

## Binaries

Download the latest version from [Releases](https://github.com/jiep/anon-sym-ake/releases).

## How to compile on Ubuntu

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

1. Run binary

```
cargo run
# or
./target/release/anon-sym-ake # for release version
./target/debug/anon-sym-ake # for debug version
```

## 🚴 Usage

```
./target/debug/anon-sym-ake --help
Usage: anon-sym-ake --kem <KEM> --sig <SIG> --clients <CLIENTS>

Options:
  -k, --kem <KEM>          
  -s, --sig <SIG>          
  -c, --clients <CLIENTS>  
  -h, --help               Print help information
  -V, --version            Print version information
```

### Example

10 clients (the protocol is executed with just one!) with Kyber1024 as KEM and Dilithium5 as Signature scheme

```
./target/release/anon-sym-ake --kem Kyber1024 --sig Dilithium5 --clients 10
[!] Generating param and seed for PQ VRF...
[!] Setting Dilithium5 as signature scheme...
[!] Setting Kyber1024 as KEM...

[!] Creating 10 clients...
[!] Creating server...

[R] Creating (ek, vk) for 10 clients...

[!] Time elapsed in registration of 10 clients is 5.891277ms

[!] Starting protocol with client0 and server...

[C] Running Round 1...
[!] Time elapsed in Round 1 is 5.6µs
[C -> S] Sending m1 to server...

[S] Running Round 2...
[!] Time elapsed in Round 2 is 58.332262ms
[C <- S] Sending m2 to client0...

[C] Running Round 3...
[C] Signature verification -> OK
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
[!] Time elapsed in Round 3 is 23.114302ms
[C -> S] Sending m3 to server...

[S] Running Round 4...
[S] Commitment verification -> OK
[!] Time elapsed in Round 4 is 58.701µs

[!] Printing session keys...
[C] 0x217f6b62a0a54caa65449074b1e2cb11505980129223896e01ff26b318b84d2d
[S] 0x217f6b62a0a54caa65449074b1e2cb11505980129223896e01ff26b318b84d2d
```