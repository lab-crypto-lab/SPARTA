// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;



contract ArrayInitialization {
    // Declare the arrays as public so they can be accessed externally
    uint[] public Rep;
    bytes32[] public HashTip;
    address[] public RegAva;
    bytes32[3] public hashChain; // Fixed-size hash chain array
    mapping(address => uint) private avatarIndex;
    string[] public result;
    // Avatar 1 Address 0x1234567890abcdef1234567890abcdef12345678
    // Avatar 2 Address 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd
    

    constructor() {
    hashChain[0] = keccak256(abi.encodePacked("SeedValue")); // H1
    hashChain[1] = keccak256(abi.encodePacked(hashChain[0])); // H2
    hashChain[2] = keccak256(abi.encodePacked(hashChain[1])); // H3
}

/*
    // ✅ Directly assign precomputed values to reduce gas costs
    constructor() {
        hashChain[0] = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890; // H1
        hashChain[1] = 0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba; // H2
        hashChain[2] = 0x456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123; // H3
}
*/
    function registerAvatar(address ava_m) public {
        require(avatarIndex[ava_m] == 0, "Already registered!"); // Ensure the avatar isn't already registered
        
        // Step 1: Store avatar address
        RegAva.push(ava_m); // Add the new avatar to the array
        avatarIndex[ava_m] = RegAva.length; // Store 1-based index in mapping

        // Step 2: Store T (H3) in HashTip[]
        bytes32 T = hashChain[2]; // Convert H3 (bytes32) to uint256
        HashTip.push(T);

        // Step 3: Compute V = H(r || u || H2)
        uint256 r = 2;
        uint256 u = 2;
        bytes32 V = keccak256(abi.encodePacked(r, u, hashChain[1])); // Compute H(2 || 2 || H2)

        // Store V in Rep[]
        
        Rep.push(uint256(V));

    }

    function getAvatarIndex(address ava_m) public view returns (int) {
        if (avatarIndex[ava_m] == 0) return -1; // If not found, return -1
        
        return int(avatarIndex[ava_m] - 1); // Convert 1-based index to 0-based
}

    function getHashChain() public view returns (bytes32[3] memory) {
        assert(hashChain[1] == keccak256(abi.encodePacked(hashChain[0]))); // ✅ Ensure H2 = keccak256(H1)
        return hashChain;
}

    // 🔹 Get the List of Registered Avatars
    function getRegAva() public view returns (address[] memory) {
        return RegAva;
    }


    function CastRep() public  {
    
        uint index = 0;
    // Step 1: Set PreImg = H2
    bytes32 PreImg = hashChain[1];

    // Step 2: Assert that H(PreImg) = HashTip[index] (ensuring T3 is stored correctly)
    assert(keccak256(abi.encodePacked(PreImg)) == HashTip[index]);

    // Step 4: Set RepTkn = H(u || r || H2)
    uint256 r = 2;
    uint256 u = 2;
    bytes32 RepTkn = keccak256(abi.encodePacked(r, u, hashChain[1])); // ✅ Compute RepTkn (same as stored in Rep[])

    // Step 5: Ensure `Rep[index]` is set
    require(Rep.length > index, "Rep is empty or index out of bounds!"); // ✅ Prevents out-of-bounds access

    // Step 6: Assert that RepTkn == Rep[index] (with proper type conversion)
    assert(uint256(RepTkn) == Rep[index]); // ✅ Ensures stored value is correct

    // ✅ Step 7: Update Rep[index] with RepTkn
    Rep[index] = uint256(RepTkn);

    // ✅ Step 8: Store Avam || "session was good" in result[]
    result.push(string(abi.encodePacked(" session was good")));

    // ✅ Step 9: Update HashTip[index] with H2
    HashTip[index] = hashChain[1]; // ✅ Store H2 in HashTip[index]
}



}