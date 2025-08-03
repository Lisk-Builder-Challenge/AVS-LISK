// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../src/Interfaces/IYieldzAVS.sol";

contract MockYieldzAVS is IYieldzAVS {
    mapping(address => Loan) public loans;
    uint256 public totalSupplyValue = 1000 ether; // Untuk IERC20
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    function borrowFund(address _vault, address operator, uint256 amount, uint256 interestRate, uint256 maturity) external {
        loans[operator] = Loan(amount, interestRate, block.timestamp, maturity);
    }
    function distributeYield(address _vault, uint256 amount) external {}
    function repayByAVS(address _vault, address operator, uint256 amount) external {}
    function getLoanDetails(address operator) external view returns (uint256, uint256, uint256, uint256) {
        Loan memory loan = loans[operator];
        return (loan.amount, loan.interestRate, loan.borrowedAt, loan.maturity);
    }

    // Implementasi IERC20
    function totalSupply() external view returns (uint256) { return totalSupplyValue; }
    function balanceOf(address account) external view returns (uint256) { return balances[account]; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
    function allowance(address owner, address spender) external view returns (uint256) { return allowances[owner][spender]; }
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