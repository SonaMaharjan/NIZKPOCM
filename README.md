# NIZKPOCM
<b>Java Implementation of Non-Interactive Zero Knowledge Proof of Correct Multiplication</b>

The purpose of Proof of Correct Multiplication is to prove that a ciphertext is the correct multiplication of two given ciphertexts under a given public key pk. Namely, c = a * b where a, b and c are given. 

The implementation of this Zero Knowledge Proof will correctly validate whether the message of the ciphertext <i>E</i>(<i>a</i>) was indeed multiplied by a constant &alpha;. This is done without revealing the value &alpha; and without interaction.
  
This protocol is given on p. 40 in <i>Multiparty Computation from Threshold Homomorphic Encryption</i> by Cramer, Damg&aring;rd, and Nielsen.

@author Murat Kantarcioglu
@author Sean Hall
@author James Garrity

<b>Implementation</b>

The proof has been built on the existing paillier cryptosystem library. 

Incase the programs do not run, compile them first using the following command in the terminal.
	javac -d . NameOfProgram.java
