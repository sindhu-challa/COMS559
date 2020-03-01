import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {

	public static void main(String[] args) throws Exception {
		try {
			ServerSocket serverSocket = new ServerSocket(Integer.parseInt(args[0]));

			System.out.println("Sever Started ..... !!");

			Socket socket = serverSocket.accept();

			System.out.println("Client connection successful ..... !!");

//			Reader to read messages from client.
			DataInputStream messageReader = new DataInputStream(socket.getInputStream());
			
//			PrintStream to send data to client
			DataOutputStream messageWriter = new DataOutputStream(socket.getOutputStream());

			while (true) {
				int encryptionDataSize = messageReader.readInt();
				int length = messageReader.readInt();
				
				if (length > 0) {
					
					byte[] clientData = new byte[length];
					messageReader.readFully(clientData, 0, length);
					System.out.println("Client Data Size : " + clientData.length);
					byte[] encryptedData = new byte[encryptionDataSize];
					System.arraycopy(clientData, 0, encryptedData, 0, encryptionDataSize);
					System.out.println("Decrypted message: " + decrypt(encryptedData, args[1]));
					byte[] decryptedMessage = decrypt(encryptedData, args[1]);
					byte[] digitalSignature = new byte[length - encryptionDataSize];
					System.arraycopy(clientData, length-encryptionDataSize, digitalSignature, 0, length-encryptionDataSize);				
					if(verifySignature(args[2], decryptedMessage, digitalSignature)) {
						System.out.println("Signature Verification successful.");
						System.out.println("---------- Decrypted AES Key ----------");
						System.out.println(new BigInteger(1, decryptedMessage));
					} else {
						System.out.println("Signature Verification Failed, Exiting.");
						System.exit(0);
					}
					SecureRandom random = new SecureRandom();
					byte[] IV = new byte[16]; // 128 bits are converted to 16 bytes;
					random.nextBytes(IV);
					byte[] fileData = readFile(args[3]);
					byte[] encryptedFileData = AESEncrypt(decryptedMessage, fileData, IV);
					byte[] serverData = new byte[IV.length + encryptedFileData.length];
					System.arraycopy(encryptedFileData, 0, serverData, 0, encryptedFileData.length);
					System.arraycopy(IV, 0, serverData, encryptedFileData.length, IV.length);
					System.out.println("---------- CipherText ----------");
					System.out.println(new BigInteger(1, encryptedFileData));
					messageWriter.writeInt(serverData.length);
					messageWriter.writeInt(IV.length);
					messageWriter.write(serverData);
				}

				messageWriter.close();
				messageReader.close();
				socket.close();
				serverSocket.close();

				System.exit(0);
			}

		} catch (IOException e) {
			System.out.println("Error while opening socket");
			e.printStackTrace();
		}
	}
	
	
	public static byte[] readFile(String filename) throws Exception {
		Path path = Paths.get(filename);
	    byte[] data = Files.readAllBytes(path);
	    System.out.println("---------- File data provided by the user ----------");
	    System.out.println(new String(data));
		return data;
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
