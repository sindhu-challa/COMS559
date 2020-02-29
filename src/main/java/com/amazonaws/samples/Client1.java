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
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Client1 {

	
	private Socket socket;
	private static final String keyServer  = "/Users/lakshmisindhurachalla/Desktop/559_Cloud_Computing_Docs/ServerKeys";
	private static final String keyClient  = "/Users/lakshmisindhurachalla/Desktop/559_Cloud_Computing_Docs/ClientKeys";
	
	public Client1(Socket socket){
		this.socket = socket;
	}
	
	//Load Public key & private keys 
	
	
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
	
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		
		// Initialize connection to server's socket
		String hostName = "127.0.0.1";
		int portNumber = 4000;

//		// Initialize the IO from server
//		try (Socket socket = new Socket(hostName, portNumber);
//				OutputStream out = socket.getOutputStream();
//				DataOutputStream dos = new DataOutputStream(out);
//				InputStream in = socket.getInputStream();
//			    DataInputStream dis = new DataInputStream(in);) {
//			Client client = new Client(socket);
//			
//			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
//	
//			
			// Generate AES session key
		SecureRandom secureRandom = new SecureRandom();
		byte[] key = new byte[16];
		secureRandom.nextBytes(key);
		SecretKey secretKey = SecretKeySpec(key, "AES");
			System.out.println(keyK);
			
			
		}
	
}
