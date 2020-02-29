package com.amazonaws.samples;

//A Java program for a Server 
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.net.*;

public class Server {
	
	private static final String keyServer  = "/Users/lakshmisindhurachalla/Desktop/559_Cloud_Computing_Docs/ServerKeys";
	private static final String keyClient  = "/Users/lakshmisindhurachalla/Desktop/559_Cloud_Computing_Docs/ClientKeys";

	public static KeyPair loadKeyPair(String path, String algorithm)
		      throws IOException, NoSuchAlgorithmException,
		      InvalidKeySpecException {
		    // read public key from file
		    File filePublicKey = new File(path + "/public.key");
		    FileInputStream fis = new FileInputStream(filePublicKey);
		    byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		    fis.read(encodedPublicKey);
		    fis.close();

		    // read private key from file
		    File filePrivateKey = new File(path + "/private.key");
		    fis = new FileInputStream(filePrivateKey);
		    byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		    fis.read(encodedPrivateKey);
		    fis.close();

		    // Convert them into KeyPair
		    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
		        encodedPublicKey);
		    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

		    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
		        encodedPrivateKey);
		    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

		    return new KeyPair(publicKey, privateKey);
		  }
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {

		String keyDir  = "/Users/lakshmisindhurachalla/Desktop/559_Cloud_Computing_Docs";
		int portNumber = 4000;
		Socket socket   = null; 
	    DataInputStream in  =  null; 
	    
		// Server initializes the socket it must listen on
		try (ServerSocket server = new ServerSocket(portNumber);) {
			System.out.println("Server started"); 
			  
            System.out.println("Waiting for a client ..."); 
  
            socket = server.accept(); 
            System.out.println("Client accepted"); 
            
            
         // takes input from the client socket 
            in = new DataInputStream( 
                new BufferedInputStream(socket.getInputStream())); 
            
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
			SecretKey sessionKey = keygen.generateKey();
            byte[] iv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			IvParameterSpec ips = new IvParameterSpec(iv);
            Cipher sessionDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			sessionDecryptCipher.init(Cipher.DECRYPT_MODE, sessionKey, ips);
  
            int len;
            DataInputStream dis = new DataInputStream(in);
            
            MessageDigest md = MessageDigest.getInstance("SHA-256");
			while (true) {
            // reads message from client until "Over" is sent 
            if (in.available() != 0){
            	len = dis.readInt();
			    byte[] inputInByteArray = new byte[len];
			    if (len > 0) {
			        dis.readFully(inputInByteArray);
			    }

				len = dis.readInt();
			    byte[] hash = new byte[len];
			    if (len > 0) {
			        dis.readFully(hash);
			    }
			    
				System.out.println("Received Encrypted Message:" + new String(inputInByteArray));
				System.out.println("hash:" + hash);
				

				KeyPair loaded = loadKeyPair(keyDir, "RSA");
		

					byte[] decryptedInput = sessionDecryptCipher.doFinal(inputInByteArray);
					String decryptedMessage = new String(decryptedInput);
					
					// Rebuilding hash
					byte[] rebuiltHash = new byte[decryptedInput.length + sessionKey.getEncoded().length];
					System.arraycopy(decryptedInput, 0, rebuiltHash, 0, decryptedInput.length);
					System.arraycopy(sessionKey.getEncoded(), 0, rebuiltHash, decryptedInput.length, sessionKey.getEncoded().length);

				    byte outputHash[] = md.digest(rebuiltHash);
					
				    // Validating hash Signature
					if (Arrays.equals(hash, outputHash)){
						System.out.println("Hash match!");
					} else {
						System.out.println("Hashes do not match! Decrypted message may be garbled and/or tempered with.");
					}
					
					// Displaying message
					System.out.println("Decrypted:" + decryptedMessage);
					
					if (decryptedMessage.equalsIgnoreCase("Bye."))
						break;
			}
			}
		
		System.out.println("Closing connection"); 
		  
	    // close connection 
	    socket.close(); 
	    in.close(); 
			// Catch exceptions
			} catch(IOException i){
				System.out.println("Exception caught when trying to listen on port");
				System.out.println(i.getMessage());
		}
			
			}
	
	
}
