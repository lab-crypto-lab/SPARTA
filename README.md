# SPARTA  

This repository contains the implementation of **SPARTA**: a **S**ecure and **P**rivacy-preserving protocol with **R**ole separation and **T**rustworthiness for **A**vatars in the metaverse. SPARTA enables avatar authentication while maintaining avatar unlinkability.

## Implementation Overview  

The implementation is divided into two parts:  

- **Python Implementation**: A Mercurial-based authentication system.  
- **Smart Contract (Solidity)**: A reputation mechanism for trust evaluation.  

Additionally, we provide cryptographic execution time calculations for the cryptographic primitives used in the protocol.
    
## Socket Programming (Python) Implementation 
A Python socket programming implementation of SPARTA to simulate the flow of our protocol messages between the two avatars M and N in a real-time experiment and to measure the end-to-end latency. The avatar M is represented on the Raspberry Pi 5 with a 2.4 GHz quad-core 64-bit Arm Cortex-A76 CPU and avatar N is represented on the macbook pro with a 2.4 GHz quad-core 64-bit Arm Cortex-A76 CPU. This implementation shows the completeness of our the protocol and the authentication between the two avatars.

## Smart Contract (Solidity) Implementation
The Solidity implementation of the SPARTA protocol. It ensures secure and efficient protocol execution, enabling seamless avatar interactions and reputation management. It consists of three algorithms:
  - Initialization
  - AvatarReg
  - CastRep


## Cryptographic execution time calculations
Calculates execution time needed to evaluate different cryptographic operations using Raspberry pi5 listed below:
  - Hashing to G1
  - Hashing to G2
  - Modular Inverse
  - Pairing
  - Scalar Multiplication
  - Point Addition
  - Modular EXponentation
  - Random Scalar generation
