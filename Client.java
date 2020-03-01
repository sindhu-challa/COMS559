import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Random;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {

	public static void main(String args[]) throws Exception {
		try {
			
//			It generates a 128 bit key to be used as symmetric key for AES.
			SecureRandom random = new SecureRandom();
			byte[] K_Byte = new byte[16]; // 128 bits are converted to 16 bytes;
			random.nextBytes(K_Byte);
			BigInteger K = new BigInteger(1, K_Byte);
			System.out.println("Generate 128 bit random number for AES Key " + K);
//			Encrypting Symmetric key with the public key of the server.
			byte[] EncryptedK = encrypt(K_Byte, args[3]);
			byte[] digitalSignature = getSignature(args[2], K_Byte);
			byte[] clientData = new byte[EncryptedK.length + digitalSignature.length];
			System.arraycopy(EncryptedK, 0, clientData, 0, EncryptedK.length);
			System.arraycopy(digitalSignature, 0, clientData, EncryptedK.length, digitalSignature.length);
			System.out.println("---------- Client side data ----------");
			System.out.println("Cipher Text in byteform: " + EncryptedK);
			System.out.println("Cipher Text in Big Integer: " + new BigInteger(1, EncryptedK));
			System.out.println("Signature in byteform: " + digitalSignature);
			System.out.println("Signature in Big Integer: " + new BigInteger(1, digitalSignature));
			Socket socket = new Socket(args[0], Integer.parseInt(args[1]));
//			Write message to server
			DataOutputStream messageWriter = new DataOutputStream(socket.getOutputStream());
//			Read message from server
			DataInputStream messageReader = new DataInputStream(socket.getInputStream());

			for (int i = 0; i < 1; i++) {
				messageWriter.writeInt(EncryptedK.length);
				messageWriter.writeInt(clientData.length);
				messageWriter.write(clientData);

				// receive from the server
				int length = messageReader.readInt();
				byte[] serverData = new byte[length];
				int IVLength = messageReader.readInt();
				messageReader.readFully(serverData, 0, length);
				byte[] IV = new byte[IVLength];
				byte[] fileData = new byte[length - IVLength];
				System.arraycopy(serverData, 0, fileData, 0, length - IVLength);
				System.arraycopy(serverData, length - IVLength, IV, 0, IVLength);

				String decryptedData = new String(AESDecrypt(K_Byte, fileData, IV));
				
				System.out.println("---------- Data from Server after decryption ----------");
				System.out.println("File Data from user: " + new String(decryptedData));
			}
			messageWriter.flush();
			messageWriter.close();
			socket.close();
			System.exit(0);
		} catch (Exception e) {
			System.out.println("Error while connecting to server");
			e.printStackTrace();
		}
	}
	
	public static byte[] encrypt(byte[] data, String publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
		return cipher.doFinal(data);
	}

	public static PublicKey getPublicKey(String publicKey) throws Exception {
		byte[] keyBytes = Files.readAllBytes(Paths.get(publicKey));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public static PrivateKey getPrivateKey(String filename) throws Exception {

		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	public static byte[] decrypt(byte[] data, String privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
		return cipher.doFinal(data);
	}

	public static byte[] getSignature(String privateKey, byte[] data) throws Exception {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(getPrivateKey(privateKey));
		signature.update(data);
		return signature.sign();
	}

	public static boolean verifySignature(String publicKey, byte[] data, byte[] receivedSignature) throws Exception {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(getPublicKey(publicKey));
		signature.update(data);
		return signature.verify(receivedSignature);
	}

	public static byte[] AESEncrypt(byte[] key, byte[] data, byte[] IV) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec IVspec = new IvParameterSpec(IV);
		SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, IVspec);
		return cipher.doFinal(data);
	}

	public static byte[] AESDecrypt(byte[] key, byte[] data, byte[] IV) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec IVspec = new IvParameterSpec(IV);
		SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, IVspec);
		return cipher.doFinal(data);
	}
}
