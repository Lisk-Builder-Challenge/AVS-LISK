//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

interface IVault is IERC20 {
    function deposit(uint256 amount) external;

    function withdraw(uint256 amount) external;

    function borrowByAVS(uint256 amount) external;

    function distributeYield(uint256 amount) external;

    function balanceOfUnderlying(address user) external view returns (uint256);

    function convertToAssets(uint256 shares) external view returns (uint256 assets);

    function convertToShares(uint256 assets) external view returns (uint256 shares);
}
