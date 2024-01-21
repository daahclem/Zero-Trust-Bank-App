// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BankAppAuth {
    struct User {
        string username;
        bytes32 passwordHash; // Storing the hash of the password
        string role; // User role for access controlA
        bool isRegistered;
    }

    mapping(address => User) public users;

    event UserRegistered(address userAddress, string username, string role);
    event UserAuthenticated(address userAddress);

    // Function to register a new user
    function registerUser(address _userAddress, string memory _username, bytes32 _passwordHash, string memory _role) public {
        require(!users[_userAddress].isRegistered, "User already exists.");
        users[_userAddress] = User(_username, _passwordHash, _role, true);
        emit UserRegistered(_userAddress, _username, _role);
    }

    // Function to authenticate a user
    function authenticateUser(address _userAddress, bytes32 _passwordHash) public returns (bool) {
        require(users[_userAddress].isRegistered, "User not registered.");
        require(users[_userAddress].passwordHash == _passwordHash, "Invalid credentials.");
        emit UserAuthenticated(_userAddress);
        return true;
    }

    // Function to get user role
    function getUserRole(address _userAddress) public view returns (string memory) {
        require(users[_userAddress].isRegistered, "User not registered.");
        return users[_userAddress].role;
    }
}
