---
title: Codehawks First Flight-1 - PasswordStore
date:  2024-06-18 02:00:00
mathjax: true
categories:
  - "First Flights"
tags:
  - "Ethereum"
  - "Solidity"
  - "Exploits"
  - "Bugs"
  - "codehawks"
  - "first flight"
  - "passwordstore"
  - "shadowaudit"

mermaid: true
---
<html>
  <head>
    <script type="text/javascript" async
  src="https://cdnjs.cloudflare.com/ajax/libs/mathjax/2.7.7/MathJax.js?config=TeX-MML-AM_CHTML">
    </script>


<script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/mathjax/2.7.1/MathJax.js?config=TeX-AMS_HTML">
  MathJax.Hub.Config({
    "HTML-CSS": {
      availableFonts: ["TeX"],
    },
    tex2jax: {
      inlineMath: [['$','$'],["\\(","\\)"]]},
      displayMath: [ ['$$','$$'], ['\[','\]'] ],
    TeX: {
      extensions: ["AMSmath.js", "AMSsymbols.js", "color.js"],
      equationNumbers: {
        autoNumber: "AMS"
      }
    },
    showProcessingMessages: false,
    messageStyle: "none",
    imageFont: null,
    "AssistiveMML": { disabled: true }
  });
</script>
</head>
</html>

------

This is my Audit report for the [Codehawks First Flight #1: PasswordStore](https://codehawks.cyfrin.io/c/2023-10-PasswordStore "Codehawks First Flight #1: PasswordStore"). Although it's a bit late to be auditing this contract, first flights are one of the best ways to dip one's toes in the vast ocean of Smart Contract Audits. This being the first one in the series is an obvious choice for a staring point. 

Happy reading!

___
## <u>Getting started</u>

This particular contest involves only a single Smart Contract [PasswordStore.sol](https://github.com/Cyfrin/2023-10-PasswordStore/blob/main/src/PasswordStore.sol). PasswordStore is a smart contract application for storing a password. Users should be able to store a password and then retrieve it later. Others should not be able to access the password.

Find the Contract below -

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

/*
 * @author not-so-secure-dev
 * @title PasswordStore
 * @notice This contract allows you to store a private password that others won't be able to see. 
 * You can update your password at any time.
 */
contract PasswordStore {
    error PasswordStore__NotOwner();

    address private s_owner;
    string private s_password;

    event SetNetPassword();

    constructor() {
        s_owner = msg.sender;
    }

    /*
     * @notice This function allows only the owner to set a new password.
     * @param newPassword The new password to set.
     */
    function setPassword(string memory newPassword) external {
        s_password = newPassword;
        emit SetNetPassword();
    }

    /*
     * @notice This allows only the owner to retrieve the password.
     * @param newPassword The new password to set.
     */
    function getPassword() external view returns (string memory) {
        if (msg.sender != s_owner) {
            revert PasswordStore__NotOwner();
        }
        return s_password;
    }
}
```

## <u>Issues</u>

### **High -**

**<u>1. The `setPassword()` function does not use any access controls.</u>**

**Impact -** The `setPassword()` function does not use any access controls and can be called by anyone to change the password.

**Mitigation -** Modifiers or other access control methods should be used to restrict access to functions handling critical functionality.

```solidity
    function setPassword(string memory newPassword) external {
        if (msg.sender != s_owner) {
            revert PasswordStore__NotOwner();
        }
        s_password = newPassword;
        emit SetNetPassword();
    }
```

**<u>2. The value of the `s_password` private variable is not actually private</u>**

**Impact -** Private information should never be stored on chain since nothing stored on chain is actually private. Any sensitive information stored in a state variable (even if it is private) can be easily retrieved by anyone.

**Mitigation -** Storing sensitive information on chain should always be avoided since everything on chain is public. Sensitive information should alwyas be stored off-chain.
