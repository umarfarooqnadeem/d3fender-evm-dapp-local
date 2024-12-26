/** @type {import('next').NextConfig} */
const nextConfig = {
  distDir: 'build',
  reactStrictMode: true,
  env: {
    projectId: 'd2fa8025c6d301d02bdb7e154a2f4931',
    chainId: "137",
    // chainId: "11155111",
    // rpcNode: "https://sepolia.infura.io/v3/3697dcd9dd1a41e3981d0033d768eb92",
    rpcNode: "https://polygon-mainnet.infura.io/v3/bcacd1ee4d4048988398f21fe7dd0c64",
    smartContract: "0xa331a8a3da2b7f1b7f4d61d74473b47d6077d354",
    smartContractABI: JSON.stringify(require('./contracts/SmartContractABI.json')),
    ERC721ABI: JSON.stringify(require('./contracts/ERC721ABI.json')),
    ERC20ABI: JSON.stringify(require('./contracts/ERC20ABI.json')),
    revenue: process.env.REVENUE?.toString() || '0', 
    baseURI: process.env.BASE_URI.toString() || "http://localhost:5000",
    delayUpdate: process.env.DEDLAY_UPDATE  || '0'
  }
}

module.exports = nextConfig

