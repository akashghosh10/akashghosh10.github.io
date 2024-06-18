---
title: Uwulend - A Casestudy on Oracle Manipulation attacks
date:  2024-06-18 02:00:00
mathjax: true
categories:
  - "Exploits"
tags:
  - "Ethereum"
  - "Solidity"
  - "Exploits"
  - "Bugs"
  - "Oracle"

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

The popular protocol, Uwulend recently played prey to one of the most nefarious attacks of 2024. It was hacked for **$19.4 M** in 3 swift transactions on June 10th. Investigations revealed the casue to be an oracle manipulation attack later. Although well-known among both developers and security researchers, this type of attack still remains to be one of the most popularly used attack vectors. This got me wondering about what the attack means and how is it done. So, I have taken to writing this article to give an overview of how an oracle manipulation attack works and what exactly happened on June 10th, 2024.

Happy reading!

___
## What is an Oracle?

An oracle acts as a middle man between on-chain smart contracts and off-chain services or events. Often, smart contracts rely on off-chain data to make decisions. It can be the price of tokens for a lending protocol, weather data or even sports results for a betting platform. These intermediaries help in procuring this off-chain data and incorporating it to trigger on-chain smart contracts.

![Image Unavailable](/images/oracle-definition.png)

## The Vulnerability

Although very essential, using an oracle can turn into a nightmare if used without caution. Since they provide off-chain data, smart contracts that rely on this data can be manipulated easily by hackers. Find the walkhrough of a generic oracle manipulation attack below -

**Step-1** The hacker borrows a large sum of money using a flash loan.
**Step-2** This money is then used to make a large swap in a decentralized exchange which inflates the price of a token in the liquidity pool. 
**Step-3** The token with the inflated price is used as collateral in a lending protocol which also derives the price of the token from the same decentralized exchange mentioned above, to borrow a large sum of another token. Since the collateral token has an inflated price, it is overvalued, and the hacker enters an insolvent position, hence walking away with a lot of money.
**Step-4** A part of the tokens borrowed is used to repay the flash loan.

![Image Unavailable](/images/oracle-manipulation-walkthrough.png)

## Uwulend

On June 10th a very similar attack to what is explained above was orchestrated on the popular lending protocol uwulend. The fallback oracle used by Uwulend incorporates a number of curve pools to determine the curent price of a token. The attacker took a flash loan from Tornado Cash to manipulate the price of the tokens in these pools. The attacker borrowed sUSDe at *0.99* and liquidated the position at *1.03*.

![Image Unavailable](/images/Uwulend-exploit-transactions.png)

The stolen funds were siphoned to two addresses. And, in a comical turn of events, a mysterious person even sent an on-chain message to the attacker advising him on how he can safely withdraw his funds keeping his identity a secret.

![Image Unavailable](/images/uwulend-attacker-message.png)

However, a protocol which was audited and declared as safe by Peckshield raises a lot of questions. The github page of the protocol doesn't showcase any tests and the involvement of the creator, 0xSifu, with a lot of prior hacks is a real red flag.

## Prevention

Protocols should always refrain from using liquidity pools as oracles since they can be very easily manipulated. Ideally, oracle services like chainlink should be used which fetch the price of tokens from a series of liquidity pools, providing an average of them as the actual price.

Uniswap which is actually a liquidity pool has employed something known as TWAP (Time Weighted Average Price), which uses the price of tokens in a series of previous blocks to determine the current price, preventing attackers from using flash loans to manipulate prices.

From an investors point of view, one should always check if proper tests have been done and review the code carefully, before staking any money in a protocol.
