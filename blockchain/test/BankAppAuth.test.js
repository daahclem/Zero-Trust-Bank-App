const BankAppAuth = artifacts.require("BankAppAuth");

const { assert } = require("chai");
const { toWei } = require("web3-utils");

contract("BankAppAuth", (accounts) => {
  let bankAppAuth;

  before(async () => {
    bankAppAuth = await BankAppAuth.deployed();
  });

  // Test for user registration
  it("should register a user", async () => {
    const userAddress = accounts[1];
    const username = "testuser";
    const passwordHash = web3.utils.sha3("password");
    const role = "customer";

    await bankAppAuth.registerUser(userAddress, username, passwordHash, role);
    const registeredUser = await bankAppAuth.users(userAddress);

    assert.equal(registeredUser.username, username, "Username does not match");
    assert.equal(registeredUser.passwordHash, passwordHash, "Password hash does not match");
    assert.equal(registeredUser.role, role, "Role does not match");
  });

  // Additional tests for other functionalities can be added here
});
