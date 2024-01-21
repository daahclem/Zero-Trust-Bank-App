const BankAppAuth = artifacts.require("BankAppAuth");

module.exports = function (deployer) {
  deployer.deploy(BankAppAuth);
};
