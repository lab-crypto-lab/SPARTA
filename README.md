# SPARTA
This is the accompanying code of smart contract and python implementation for the article "Secure and Privacy-Preserving Protocol for Multi-Context Avatars in the Metaverse". 
The implementation is divided into two parts
  - Python Implementation for Mercurial based authentication system.
  - Smart Contract using Solidity.
    
Also, provide the cryptographic execution time calculations for related cryptographic primitives used.
    
## Python Implementation 
Socket programming implementation using Raspberry pi5 and Macbook pro.
  - User M is represented on the raspberry pi5.
  - User N is represented on the macbook pro.

## Smart Contract Solidity Implementation Breakdown
It consists of three algorithms:
  - Initialization
  - AvatarReg
  - CastRep
### Initialization 
  - It consists of three lists for Reputation tokens, HashTip value, Registered avatars. 

### AvatarReg
  - Each Avatar register its Id in RegAva[] list.
  - Stores Tip of the hash chain in HashTip[] list.
  - Stores Reputation token in Rep[] list.

### CastRep 
  - Upon interaction between avatars, each Avatar checks that H(PreImg) received is equal to the hashtip stored.
  - each avatar checks that H(RepTKN) received is equal to Rep value stored, then updates REP[] with REPTKN.
  - Record the session feedback
  - update HashTip[] with PreImg.

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
