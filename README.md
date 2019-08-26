# NIZKPOCM
<b>Java Implementation of Non-Interactive Zero Knowledge Proof of Correct Multiplication</b>

The purpose of Proof of Correct Multiplication is to prove that a ciphertext is the correct multiplication of two given ciphertexts under a given public key pk. Namely, c = a * b where a, b and c are given. 

The implementation of this Zero Knowledge Proof will correctly validate whether the message of the ciphertext <i>E</i>(<i>a</i>) was indeed multiplied by a constant &alpha;. This is done without revealing the value &alpha; and without interaction.
  
This protocol is given on p. 40 in <i>Multiparty Computation from Threshold Homomorphic Encryption</i> by Cramer, Damg&aring;rd, and Nielsen.

@author Murat Kantarcioglu
@author Sean Hall
@author James Garrity

<b>Implementation</b>

The proof has been built on the existing paillier cryptosystem library. Hence, encryption and decrytion are based on the paillier cryptosystem. 

<b>Building</b>

The following code from the file "MultiplicationZKP.java" computes a random encryption of <i>&alpha;a</i> where <i>a</I> is the message encrypted in {@code ca}.  This additionally sets up a Zero Knowledge Proof that this multiplication was done, without revealing anything of &alpha;.


	public MultiplicationZKP(PaillierKey key, BigInteger ca, BigInteger alpha) {
		if(!key.inModNSPlusOneStar(ca)) {
			throw new IllegalArgumentException("ca must be relatively prime to n^2 and 0 <= ca < n^2");
			//System.out.println("Hi");
		}
		
		BigInteger a=null;
		BigInteger c=null;
		BigInteger b=null;
		BigInteger d=null;
		BigInteger e=null;
		BigInteger x=null;
		BigInteger w=null;
		BigInteger t=null;
		BigInteger z=null;
		BigInteger y=null;
		BigInteger s=null;
		BigInteger u=null;
		BigInteger v=null;
		BigInteger gamma=null;
		BigInteger dummy=null;

		//System.out.println("Hi");
		
		BigInteger nSquare = key.getNSPlusOne();
		
		//c (C_alpha in the paper) is basically the encryption of alpha 
		//s is the randomness required for encrypting alpha
		//s = key.getRandomModNStar();
		s = key.getRandomModNSPlusOneStar();
		
		//gamma is the randomness required for multiplication
		//gamma = key.getRandomModNStar();
		gamma = key.getRandomModNSPlusOneStar();
		
		// calculate s^n mod nSquare 	
		//calculate (1+n)^alpha*(s^n) mod n^2
		c=((key.getNPlusOne().modPow(alpha,nSquare)).multiply(
				s.modPow(key.getN(),nSquare))).mod(nSquare);	
		
		//x is a random element from Z_N
		x = key.getRandomModN();
		
		// we need to find an u in $Z^*_{N^2}$
		u = key.getRandomModNSPlusOneStar();
		
		// we need to find a v in $Z^*_{N^2}$
		v = key.getRandomModNSPlusOneStar();
		
		//a=ca^x.v^N mod N^2
		a=((ca.modPow(x,nSquare)).multiply(v.modPow(key.getN(),nSquare))).mod(nSquare);
		
		//b=(1+n)^x u^N mod N^2
		b=((key.getNPlusOne().modPow(x,nSquare)).multiply(
				u.modPow(key.getN(),nSquare))).mod(nSquare);
		
		//ca^alpha.gamma^n mod N^2
		d=((ca.modPow(alpha,nSquare)).multiply(
				gamma.modPow(key.getN(),nSquare))).mod(nSquare);
		
		// Calculate the Hash function to create random choice e
		e = hash(ca.toByteArray(), c.toByteArray(), d.toByteArray(), a.toByteArray(), b.toByteArray());
		
		//w=x+e*alpha mod N
		dummy=x.add(e.multiply(alpha));
		w=dummy.mod(key.getN());
		t=dummy.divide(key.getN());
		
		//$z=u.s^e.(1+n)^t$
		z=((u.multiply(s.modPow(e,nSquare))).multiply(key.getNPlusOne().modPow(t,nSquare))).mod(nSquare);
		
		//y=v.ca^t.gamma^e mod n^2
		y=((v.multiply(ca.modPow(t,nSquare))).multiply(gamma.modPow(e,nSquare))).mod(nSquare);
		
		// System.out.println("n is "+ key.getN());
		// System.out.println("a is " + a);
		// System.out.println("b is " + b);
		// System.out.println("w is " + w);
		// System.out.println("z is " + z);
		// System.out.println("y is " + y);
		
		this.nSPlusOne = key.getNSPlusOne();
		this.n = key.getN();
		this.ca=ca;
		this.c=c;
		this.d=d;
		this.a=a;
		this.b=b;//for multiplication and plaintext
		this.w=w;//fpr multiplication and plaintext 
		this.y=y;
		this.z=z;//for multiplication and plaintext
		//return a;
	}

The above proof is tested by the file "check.java". 

	class check{
		public static PaillierKey publicKey;
	    private static PaillierPrivateKey privateKey;
		static Paillier paillier;
		static MultiplicationZKP demo;
	
	
	public static void main(String args[]){

		Scanner reader = new Scanner(System.in);
		System.out.println("Enter alpha: "); 
		BigInteger alpha1 = reader.nextBigInteger();
		reader.close(); 

		//long startTime = System.nanoTime();
		//********** To generate key *********
		SecureRandom sr = new SecureRandom();
		privateKey = KeyGen.PaillierKey(2048, sr.nextLong());
		publicKey = privateKey.getPublicKey();


		//********* To Encrypt the message *******
		paillier = new Paillier(publicKey);
		paillier.setDecryptEncrypt(privateKey);
		BigInteger EZERO= paillier.encrypt(new BigInteger("746"));
		//System.out.println("Encrypted message is: "+ EZERO); 


		
		//***** To make the proof *******
		demo = new MultiplicationZKP(publicKey, EZERO, alpha1);
		
		BigInteger D = demo.getValue();
		// System.out.println("D is: "+ D); 
		BigInteger alphaV = demo.alphaValue();
		//System.out.println("Encryption of Alpha is: "+ alphaV); 
		
		//********* To verify the proof *********
		Boolean Result = demo.verify();
		System.out.println("The result is: "+ Result); 
		
	} 

}

<b>Compilation </b>

First, compile each of the files using the following command in the terminal.

	javac -d . NameOfProgram.java
	
After a successful compilation, run the file "check.java" to verify the proof. 

<b>About</b>

This is a part of a research project held by Koc University. The implementation has been built on the repository created by @Princeton CITP (https://github.com/citp/ThresholdECDSA).
