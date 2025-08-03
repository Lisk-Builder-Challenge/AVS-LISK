// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../src/Interfaces/IVault.sol";

contract MockVault is IVault {
    uint256 public totalAssets = 1000 ether;
    uint256 public totalBorrowed = 0;
    uint256 public totalSupplyValue = 1000 ether; // Untuk IERC20
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalAssets += amount;
    }

    function withdraw(uint256 shares) external {
        uint256 assets = convertToAssets(shares); // Panggil fungsi internal
        require(balances[msg.sender] >= assets, "Insufficient balance");
        balances[msg.sender] -= assets;
        totalAssets -= assets;
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        // Logika sederhana: 1 share = 1 asset untuk mock
        return shares;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return assets;
    }

    function getShareToTokenRatio() external {}
    function addAssets(uint256 amount) external { totalAssets += amount; }
    function removeAssets(address operator, uint256 amount) external {
        totalAssets -= amount;
        totalBorrowed += amount;
    }
    function reduceBorrowed(uint256 amount) external { totalBorrowed -= amount; }
    function avs() external view returns (address) { return address(0); }
    function token() external view returns (address) { return address(0); }

    // Implementasi IERC20
    function totalSupply() external view returns (uint256) { return totalSupplyValue; }
    function balanceOf(address account) external view returns (uint256) { return balances[account]; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
    function allowance(address owner, address spender) external view returns (uint256) {
        return allowances[owner][spender];
    }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balances[from] >= amount, "Insufficient balance");
        require(allowances[from][msg.sender] >= amount, "Insufficient allowance");
        balances[from] -= amount;
        balances[to] += amount;
        allowances[from][msg.sender] -= amount;
        return true;
    }
}