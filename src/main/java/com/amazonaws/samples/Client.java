package com.amazonaws.samples;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Client {
	
	private Socket socket;
	private static final String keyServer  = "/Users/lakshmisindhurachalla/Desktop/559_Cloud_Computing_Docs/ServerKeys";
	private static final String keyClient  = "/Users/lakshmisindhurachalla/Desktop/559_Cloud_Computing_Docs/ClientKeys";

	public Client(Socket socket){
		this.socket = socket;
	}
	
	public void sendBytes(byte[] myByteArray, int start, int len) throws IOException {
	    if (len < 0)
	        throw new IllegalArgumentException("Negative length not allowed");
	    if (start < 0 || start >= myByteArray.length)
	        throw new IndexOutOfBoundsException("Out of bounds: " + start);
	    // Other checks if needed.

	    // May be better to save the streams in the support class;
	    // just like the socket variable.
	    OutputStream out = socket.getOutputStream(); 
	    DataOutputStream dos = new DataOutputStream(out);

	    dos.writeInt(len);
	    if (len > 0) {
	        dos.write(myByteArray, start, len);
	    }
	}

	
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
	

	public static void main(String[] args) throws IOException {
		
		// Initialize connection to server's socket
		String hostName = "127.0.0.1";
		int portNumber = 4000;

		// Initialize the IO from server
		try (Socket socket = new Socket(hostName, portNumber);
				OutputStream out = socket.getOutputStream();
				DataOutputStream dos = new DataOutputStream(out);
				InputStream in = socket.getInputStream();
			    DataInputStream dis = new DataInputStream(in);) {
			Client client = new Client(socket);
			
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

			// Generate AES session key
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			SecretKey sessionKey = keygen.generateKey();
			

			// Initialize encryption and decryption ciphers using session key
			byte[] iv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			IvParameterSpec ips = new IvParameterSpec(iv);
			Cipher sessionEncryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//			sessionEncryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ips);
			sessionEncryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ips);
			
			
			
			Cipher sessionDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			sessionDecryptCipher.init(Cipher.DECRYPT_MODE, sessionKey, ips);

			String fromUser; // message to send server
			KeyPair loadServerkey = loadKeyPair(keyServer, "RSA");
			KeyPair loadClientkey = loadKeyPair(keyClient, "RSA");
			
			int len;

			// Rebuild servers public RSA key from data received
			PublicKey pub = loadServerkey.getPublic();

			// Encrypt the AES session key with the RSA public key
			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.ENCRYPT_MODE, pub);
			// encrypt the session key with the RSA public key HERE
			byte[] encryptedSessionKey = rsaCipher.doFinal(sessionKey.getEncoded());

			// Send the server the encrypted session key in the format:
			//
			// encryptedSessionKey
			// "end key"
			//
			client.sendBytes(encryptedSessionKey, 0, encryptedSessionKey.length);
			String endKey = "end key";
			client.sendBytes(endKey.getBytes(), 0, endKey.getBytes().length);

			// Now read input from user and server.
			// With server input, messages must be decrypted using the AES
			// session key, and displayed to user
			// With user input, encrypt the messages with the AES session key,
			// display the encrypted data to user, and send to server
		    MessageDigest md = MessageDigest.getInstance("SHA-256");
			while (true) {
				
//				// Server input to client, to be displayed to user
//				if (in.available() != 0) {
//					len = dis.readInt();
//				    byte[] inputInByteArray = new byte[len];
//				    if (len > 0) {
//				        dis.readFully(inputInByteArray);
//				    }
//
//					len = dis.readInt();
//				    byte[] hash = new byte[len];
//				    if (len > 0) {
//				        dis.readFully(hash);
//				    }
//				    
//					System.out.println("Received Encrypted Message:" + new String(inputInByteArray));
//					System.out.println("hash:" + hash);
//
//					byte[] decryptedInput = sessionDecryptCipher.doFinal(inputInByteArray);
//					String decryptedMessage = new String(decryptedInput);
//					
//					// Rebuilding hash
//					byte[] rebuiltHash = new byte[decryptedInput.length + sessionKey.getEncoded().length];
//					System.arraycopy(decryptedInput, 0, rebuiltHash, 0, decryptedInput.length);
//					System.arraycopy(sessionKey.getEncoded(), 0, rebuiltHash, decryptedInput.length, sessionKey.getEncoded().length);
//
//				    byte outputHash[] = md.digest(rebuiltHash);
//					
//				    // Validating hash Signature
//					if (Arrays.equals(hash, outputHash)){
//						System.out.println("Hash match!");
//					} else {
//						System.out.println("Hashes do not match! Decrypted message may be garbled and/or tempered with.");
//					}
//					
//					// Displaying message
//					System.out.println("Decrypted:" + decryptedMessage);
//					
//					if (decryptedMessage.equalsIgnoreCase("Bye."))
//						break;
//				}
				
				// User input to client, to be sent to server
				if (stdIn.ready()) {
					fromUser = stdIn.readLine();

					// Encrypting message
					byte[] inputInByteArray = fromUser.getBytes();
					byte[] encryptedInput = sessionEncryptCipher.doFinal(inputInByteArray);
					
					// Building hash signature
					byte[] messageHash = new byte[inputInByteArray.length + sessionKey.getEncoded().length];
					System.arraycopy(inputInByteArray, 0, messageHash, 0, inputInByteArray.length);
					System.arraycopy(sessionKey.getEncoded(), 0, messageHash, inputInByteArray.length, sessionKey.getEncoded().length);
					
					byte outputHash[] = md.digest(messageHash);

					// Sending and displaying message
					System.out.println("Encrypted Message Sent: " + new String(encryptedInput));

					client.sendBytes(encryptedInput, 0, encryptedInput.length);
					System.out.println("Signature:" + new String(outputHash));
					client.sendBytes(outputHash, 0, outputHash.length);
					if (fromUser.equalsIgnoreCase("Bye."))
						break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}