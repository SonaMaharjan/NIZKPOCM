package paillierp.zkp;

import java.math.BigInteger;
import paillierp.key.*;
import paillierp.ByteUtils;
import java.util.Scanner;
import paillierp.Paillier;
import java.security.SecureRandom;
import paillierp.zkp.MultiplicationZKP;
import java.text.ParseException;
import java.util.concurrent.TimeUnit;

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

		// long endTime = System.nanoTime();
 		// long durationInNano = (endTime - startTime);  //Total execution time in nano seconds
		// //Same duration in millis
     	// long durationInMillis = TimeUnit.NANOSECONDS.toMillis(durationInNano);  //Total execution time in nano seconds
    	// System.out.println("Time in ns:"+ durationInNano);
		// System.out.println("Time in ms:"+ durationInMillis);
		
// System.out.println("Public Key is:"+ publicKey);
		// System.out.println("Private Key is:"+ privateKey);
		//BigInteger n = privateKey.getN();
		// System.out.println("N is:"+ n);