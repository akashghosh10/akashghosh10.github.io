---
title: Vulnerabilities in Upgradeable Smart Contracts
date:  2024-11-19 02:00:00
mathjax: true
categories:
  - "Vulnerabilities"
tags:
  - "Ethereum"
  - "Solidity"
  - "Exploits"
  - "Bugs"
  - "Upgradeable smart contracts"

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

## Introduction

A key feature of blockchain technology is immutability. To enable decentralization, on-chain data can't be modified post-deployment. Though this eliminates the need to rely on central authorities, it also poses a big problem for developers. Since smart contracts are essentially code that is saved on-chain, they can't be modified post-deployment as well, meaning no scope for upgradeability, bug fixes, etc. But without such essential features, blockchain technology would be useless to some extent. So, upgradeable smart contracts and various proxy patterns were introduced to enable upgardeability in smart contracts. This blog entails my take on this concept and the security measures that should be considered while writing upgradeable smart contracts.

## What is Upgradeability?

Upgradeability in smart contracts is the ability to modify or enhance the functionality of contracts post-deployment without replacing their address or state. There are various ways to achieve this but, we have settled on a particular technique as the most preferred method, the **Proxy Patterns**.

**<u>Proxy Patterns</u>**

The entire family of proxy patterns employs the same fundamental concept. The logic and storage of a protocol is seperated into atleast two contracts. The proxy contract is used for storage and remains constant throughout the various versions of the protocol. The Implementation contract contains all the logic behind the protocol. The users or EOAs interact with the proxy contract which then uses the low-level EVM function `delegatecall()` to call various functions in the implementation contract. Unlike `call()` this function helps us in calling a contract in the context of the caller contract. Meaning, the functions in the implementation contract are executed over the storage of the proxy contract. When the implementation contract needs to be upgraded, it is replaced with a new implementation contract with all the desired logic. The only change that takes place in the perspective of the proxy contract is the address of the implementation contract.

## Common Vulnerabilities

Upgradeable smart contracts are extremely common for a smart contract auditor. Most, if not all of the smart contracts that are developed nowadays are upgradeable. Owing to the lack of knowledge and human error, these contracts become susceptible to some of the most common vulnerabilities out there.

**<u>1. Storage Collision</u>**

The storage slots in Ethereum are fixed and shared across contract implementations. So, the proxy and the implementation contract must have the same storage layout. More importantly, during upgrades, this layout needs to be same. If the order in which the variables are declared is changed, this leads to storage clashes. For example, look at the initial implementation contract.

```
// Implementation V1
contract LogicV1 {
    uint256 public value; // Storage slot 0
    address public owner; // Storage slot 1

    function setValue(uint256 _value) external {
        value = _value;
    }
}
```

Let's say we upgrade this implementation and replace it with the contract below.

```
// Implementation V2
contract LogicV2 {
    address public owner; // Storage slot 0 (clash with `value` in V1)
    uint256 public newValue; // Storage slot 1 (clash with `owner` in V1)

    function setNewValue(uint256 _value) external {
        newValue = _value;
    }
}
```

Here, since the order in which the variables were declared in the upgraded contract was reversed, when owner is updated it will actually update the variable stored in slot 0 of the proxy contract which is essentially the value variable, and vice versa.

This same logic will apply when new variables are added. If new variables are added in a way that overlaps with the already existing storage slots, when those variables are updated, the acual change will happen to the already stored variables in the proxy contract.

The mitigation for this is very simple. When upgrading implementation contracts, the existing storage layout should be preserved, i.e the order of variable declaration should be kept same. If new variables are to be added, it must be done after the existing variables. Additionally, storge gaps should be added to reserve storage for future variable addition.

The ethernaut challenges explore this vulnerability in it's 24th challenge. Find my blog on it [here](https://akashghosh10.github.io/posts/ethernaut/#level-24-puzzle-wallet).

**<u>2. Use of Constructors</u>**

Upgradeable contracts rely on proxy patterns where the proxy delegates calls to an implementation contract. During deployment, constructors are executed only once for the implementation contract, not the proxy, leaving critical initialization incomplete for the proxy. Constructors can’t be re-executed or modified, and initialization logic tied to constructors won't transfer to the proxy, potentially leaving the system in an uninitialized or vulnerable state. 

The solution to this problem is to place the code in the constructor to an initializer function. This function should be explicitly called whenever the proxy is linked to the logic contract. To maintain security, the initializer function must be designed to execute only once, mimicking the behavior of a constructor in traditional programming. Openzeppelin provide it's initializable contract and the initializer modifier to ensure this functionality. All we need to do is inherit for the contract and use the modifier.

```
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyContract is Initializable {
    function initialize(
        address arg1,
        uint256 arg2,
        bytes memory arg3
    ) public payable initializer {
        // "constructor" code...
    }
}
```

**<u>3. Uninitialized contracts and Selfdestruct</u>**

As explained in the last section, constructors shouldn't be used in implementation contracts. Instead, the code in the constructor should be replaced into a seperate intializer function that should be delegate-called to once the proxy contract is linked to the implementation contract. However, if the developer fails to initialize the proxy contract, it can cause serious problems. For example, let's consider a hypothetical attack performed on an uninitialized proxy that use the UUPS proxy pattern, wherein the upgrade logic is plcaed in the implementation contract itself.

1. The attacker calls initialize() on the implementation contract to become the owner. Note that initialize() makes the first person to call it the owner. Since nobody has called this function yet in the context of the implementation, the call works and makes the attacker the owner.
2. Attacker deploys a malicious contract with a selfdestruct() function
3. The attacker calls upgradeToAndCall() on the implementation contract as an owner, and points it to the malicious selfdestruct contract
4. During the upgradeToAndCall() execution, DELEGATECALL is called from the implementation contract to the malicious selfdestruct contract using the context of the implementation contract (not the proxy)
5. SELFDESTRUCT is called, destroying the implementation contract
6. The proxy contract is now rendered useless without an implementation contract.

A very similar attack was perfomed on Wormhole’s uninitialized proxy. Find immunefi's breakdown of the attack [here](https://medium.com/immunefi/wormhole-uninitialized-proxy-bugfix-review-90250c41a43a).

**<u>4. Use of Immutable Variables</u>**

The value of immutable variables are set during contract deployment and cannot be updated. In an upgradeable contract, only the proxy is deployed permanently, while the logic contract can change. Since immutable variables are hardcoded in the logic contract, any upgrade to the logic contract will not carry forward the values of these variables. A variable instantiated as immutable would result in all proxies pointing to the same value stored in byte code, rather than the proxy pointing to the variable in it's own storage. Using storage variables instead ensures compatibility across upgrades.

**<u>5. Function Clashing</u>**

Proxies work by delegating all calls to a logic contract. However, the proxies need some functions of their own too. If two functions with the same function signature exists, one in the proxy and the other in the implementation contract, this can be confusing as to which function the user wants to call. This is solved by using the Transparent Proxy pattern wherein, a check is performed on `msg.sender`. If it is the admin, the function in the proxy is called. However, if it is any other address, then the call is delegated to the implementation contract. Although this consumes more gas due the extra checks, this solves the problem.

## Conclusion

In the section above, I have listed some of the commonly seen vulnerabilities in upgradable smart contracts and how they are mitigated. Although very important, those alone are not enough to ensure complete security of the smart contracts. All best practices like implementation of proper access control, testing, event logging, etc. should be implemented along with the mitigations to ensure versatile upgrade mechanisms.

## Additional Resources
1. [Smart Contract Upgradeability 101 by Owen Thurm](https://www.youtube.com/watch?v=e5lWvt1rIm0)
2. [A Comprehensive Survey of Upgradeable Smart Contract Patterns](https://arxiv.org/abs/2304.03405)
3. [Proxy upgrade patterns by Openzeppelin](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies)
4. [Attack on Wormhole](https://medium.com/immunefi/wormhole-uninitialized-proxy-bugfix-review-90250c41a43a)
5. [Ethernaut's Level 24 - An example of the storage collision vulnerability](https://akashghosh10.github.io/posts/ethernaut/#level-24-puzzle-wallet)
