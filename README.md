# 2019-defcon27-capture-the-coin
(WIP) Write-up on my progress on https://capturethecoin.org/



## Blockchain

### 100 Satoshi's Secret
A Bitcoin address is an encoding of a partial bitcoin script. Spending the bitcoins at an address requires providing the rest of the script in such a way that the script leaves an empty stack. Usually, the only way to complete the script is to provide a valid digital signature of the public key where the coins have been assigned. More can be found on the Bitcoin Wiki: https://en.bitcoin.it/wiki/Script

This puzzle doesn't require providing a digital signature, but it does require that you know how to complete the script.

What is the unlocking script required to spend the output to BTC testnet transaction TXID :
`23c9470a2269cf6430569afdd3e2e8f35f633b6cdbc34107ddbab932c4146ba3`


### 200 Hide and Seek
We found a mnemonic for a wallet with a note saying there is a hidden transaction:

play fever bullet unlock error palm insect pottery tower torch memory liquid

Can you find the exact amount transferred on the BTC Testnet network?


### 300 Evil Droid
[evil-droid.apk](evil-droid.apk)
Someone sent us an Android malware sample saying that it stole all their BTC coins. Can you extract the evil address where all the money is sent?


### 400 Daily Double...spend
[doublespend.json](doublespend.json)
Background: JankExchange.io recently added support for a newly implemented asset called MathToken (MTK). Unfortunately, JankExchange failed to properly vet the security of MTK, and a week after adding support found themselves victim of a double spending attack. JankExchange has now hired you, a blockchain forensics specialist, to discover where the doublespend occurred, and what address double spent the funds!

MathToken: MathToken is a new digital asset that is similar, but not an exact replica of Bitcoin. In MTK, a transaction is sent from a single sender to a single receiver. An MTK transaction consolidates multiple inputs (in_txos) and constructs multiple outputs (out-txos). Blocks contain transactions, along with other metadata.

Data: JankExchange, fortunately, has a dump of blockchain state that they have helpfully provided for you to analyze. The data is provided in a JSON format. At a high level, the data provides forty consecutive snapshots of the MTK blockchain, where each snapshot is taken when a new block is committed to the blockchain. Each snapshot is a list of the ten newest blocks in the MTK blockchain. Each block contains its hash (a unique identifier), block height, its parent hash and a list of transactions. Each transaction contains a transaction id, a list of in_txos, a list of out_txos, a sender and a receiver.


### 500 Tricky Ether
Can you cause the ethereum contract below to self destruct?

```solidty
pragma solidity ^0.5.10;

contract Jackpot {

    address public owner;

    constructor() public payable {
        owner = msg.sender;
    }

    function destroyme() public {
        require(msg.sender == owner);
        selfdestruct(msg.sender);
    }

    function hackme(address _address) public {
        _address.delegatecall("0x12345678");
    }
}
```
Cause the contract at [https://ropsten.etherscan.io/address/0x5dD8D73555b63e0194405A85E114176DeCF43336](0x5dD8D73555b63e0194405A85E114176DeCF43336) to selfdestruct itself.



## Cryptography

### 100 AES Encryption Flaw
We’ve encrypted some data using the `encrypt` function defined below. Your task is to identify the flaw in the implementation and submit the plaintext of the provided ciphertext.

```ruby
# Returns ciphertext and encrypted iv in hex format
def encrypt(message)
  require 'openssl'

  # Encrypt the message using random key+iv with AES-128-OFB
  cipher = OpenSSL::Cipher.new('AES-128-OFB').encrypt
  random_key = cipher.random_key
  cipher.key = random_key
  random_iv = cipher.random_iv
  cipher.iv = random_iv
  ciphertext = cipher.update(message) + cipher.final

  # Encrypt the IV with AES-128-ECB
  simple_cipher = OpenSSL::Cipher.new('AES-128-ECB').encrypt
  simple_cipher.key = random_key
  encrypted_iv = simple_cipher.update(random_iv) + simple_cipher.final

  {
    ciphertext: ciphertext.unpack('H*').first,
    encrypted_iv: encrypted_iv.unpack('H*').first
  }
end
```

Data
```
Ciphertext:   0x1b08dbade73ae869436549ba781aa077
Encrypted IV: 0x6f60eadec7539b4930002a8a49289343a7c0024b01568d35d223ae7a9eca2b5c
```


### 200 ECDSA Nonce Reuse
The data below is provides two hex encoded ECDSA-SHA256 signatures using the secp256k1 curve for the provided public key. These signatures were generated using the same nonce value which allows recovery of the private key.

Your task is to find the private key and submit it (hex encoded with 0x prefix) as the solution to this challenge.

Data
```
Pubkey (SER-compressed): 0x2341745fe027e0d9fd4e31d2078250b9c758e153ed7c79d84a833cf74aae9c0bb
Sig #1 (msg): what up defcon
Sig #1 (r, s): (0x5d66e837a35ddc34be6fb126a3ec37153ff4767ff63cbfbbb32c04a795680491, 0x1a53499a4aafb33d59ed9a4c5fcc92c5850dcb23d208de40a909357f6fa2c12c)
Sig #1 (msg): uh oh this isn't good
Sig #2 (r, s): (0x5d66e837a35ddc34be6fb126a3ec37153ff4767ff63cbfbbb32c04a795680491, 0xd67006bc8b7375e236e11154d576eed0fc8539c3bba566f696e9a5340bb92bee)
```


### 300 Linkable Payments
[err_log.json](txs.json)
[txs.json](txs.json)
Overview
Your goal is to recognize a flaw in a particular implementation of a digital currency client, that utilizes CryptoNote key/transaction model, and use it to get the tracking key of the node running this client.

Setup
The node that you are targeting is misconfigured; it's error log is publicly accessible via a RPC endpoint. What is relevant for this challenge are log entries created by the function that checks every transaction that passes through the node.

You construct and broadcast a series of invalid transactions. These transactions are recored in txs.json . Many other fields that would be present in a real transaction are omitted for brevity.

Althought the broadcasted transactions are invalid, with this particular node you can see error messages mentioning these transactions appearing in the node's aforementioned error log. These log entries are recorded in err_log.json.

Using this information, find the tracking key of the node owner. This tracking key is the flag for the challenge. The flag must be submitted in hex format.

Technical details
Read section 4.3 of CryptoNote v2.0 whitepaper to understand how a node is supposed to process transactions To simplify the challenge a little, the destination key is P=rA and P'=aR. Then, the tracking key is not the pair (a, B), but just a (a single 160-bit hexadecimal number). B would be known to us anyway in a real-world scenario, and is irrelevant for this challenge, since it's not used in the key calculation.

The elliptic curve used by the digital currency in this challenge is brainpoolP160r1. It's a 160-bit curve, so a point on the curve is a pair of 160-bit numbers. A point on the curve is serialized as follows: 0xXXXXYYYY, where XXXX is a 160-bit hexadecimal number corresponding to the x-coordinate of the point and YYYY is another 160-bit number in hex corresponding to the y-coordinate of the point. Both coordinates are left-padded with zeros when needed, so that the resulting number of hexadecimal digits is always 40 for each coordinate. These two numbers are then concatenated together and prefixed with 0x. Thus the total length of a serialized ECC point is 82 characters.

Appendix
It's important to note that the node operator's funds are still safe since the spending key is not stored on the node or used for transaction scanning. But now you can set up your own tracking node and watch every transaction that is sent to the node operator, defeating the unlinkable payments model.


### 400 Schnorrer Signature
[files](files)


### 500 Forging A Signature
[pdf](pdf)


## Trivia

### 10 1337 Block
What BTC address received the coinbase reward in block 1337?

### 10 Satoshi
Input how many satoshis are in 1 Bitcoin

### 10 EVM
What is the most expensive opcode (mnemonic) in Ethereum EVM?

### 10 DAO Collapse
This bug caused the June 2016 DAO collapse

### 10 Dai
What is the contract address for Dai stablecoin (v1.0)?

### 10 Contract Owner
What is the owner address for the following Ethereum contract: 0x0882477e7895bdC5cea7cB1552ed914aB157Fe56 ?

### 10 P2SH
What number do P2SH addresses start with?

### 10 SegWit
What prefix do SegWit Bech32 addresses start with?

### 20 CoinDash-ed
Find the address used to siphon funds from CoinDash ICO using the short address attack

### 20 Hidden Message
The following transaction contains a number of outputs with hidden messages in them:
`8881a937a437ff6ce83be3a89d77ea88ee12315f37f7ef0dd3742c30eef92dba`

Find the output address containing the message that includes the famous world leader’s name, Nelson Mandela.

### 30 Reorg
On May 15, 2019 a blockchain reorg has occurred on the BCH network. What is the hash for the orphaned block #582698?

### 40 Pizza
What is the public key associated with the address used to send 10,000 BTC to buy pizza on May 22, 2010. Transaction hash:
`a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d`
