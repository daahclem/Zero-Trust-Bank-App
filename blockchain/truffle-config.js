module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 7545, // Default port for Ganache
      network_id: "*", // Connects to any network
    },
    // Other network configurations can be added here
  },
  mocha: {
    // timeout: 100000
  },
  compilers: {
    solc: {
      version: "0.8.0", // Match the version with the Solidity version in BankAppAuth.sol
      settings: {
        optimizer: {
          enabled: false,
          runs: 200,
        },
      },
    },
  },
  // Configure the DB 
  db: {
    enabled: false,
  },
};
