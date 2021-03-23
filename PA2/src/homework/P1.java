package homework;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class P1 {
	private static final String ALGORITHM = "RSA";
	private static final String ALGORITHM_HYBRID = "AES/CBC/PKCS5Padding";
	
	public static IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(n);
		SecretKey key = keyGenerator.generateKey();
		return key;
	}
	
	public static byte[] wrapKey(PublicKey pk, SecretKey sk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.WRAP_MODE, pk);
		byte[] wrapped = cipher.wrap(sk);
		return wrapped;
	}
	
	public static SecretKey unwrapKey(PrivateKey pk, byte[] skWrapped) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.UNWRAP_MODE, pk);
		SecretKey key = (SecretKey) cipher.unwrap(skWrapped, ALGORITHM_HYBRID, Cipher.SECRET_KEY);
		return key;
	}
	//Returns the secret key encrypted
	public static byte[] encrypt_hybrid(SecretKey key, IvParameterSpec iv, File input, File output, KeyPair kp) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher cipher = Cipher.getInstance(ALGORITHM_HYBRID);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		FileInputStream is = new FileInputStream(input);
		FileOutputStream os = new FileOutputStream(output);
		
		byte[] buffer = new byte[64];
		int i;
		while((i=is.read(buffer))!=-1){
			byte[] ciphered = cipher.update(buffer, 0, i);
			if(ciphered!=null) {
				os.write(ciphered);
			}
		}
		byte[] lastCiphered = cipher.doFinal();
		if(lastCiphered!=null) {
			os.write(lastCiphered);
		}
		is.close();
		os.close();
		
		//Generate the secretkey's encryption
		byte[] secretKeyWrapped = wrapKey(kp.getPublic(), key);
		return secretKeyWrapped;
	}
	
	public static void encrypt_rsa(PublicKey pk, File input, File output) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, pk);
		FileInputStream is = new FileInputStream(input);
		FileOutputStream os = new FileOutputStream(output);
		//Max padding for rsa
		byte[] buffer = new byte[245];
		int i;
		while((i=is.read(buffer))!=-1) {
			byte[] ciphered=cipher.doFinal(buffer);
			os.write(ciphered);
		}
		
		is.close();
		os.close();
	}
	
	
	
	public static void decrypt_hybrid(SecretKey k2, IvParameterSpec iv, File input, File output, KeyPair kp, byte[] skWrapped) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
			SecretKey key = unwrapKey(kp.getPrivate(), skWrapped);
			Cipher cipher = Cipher.getInstance(ALGORITHM_HYBRID);
			cipher.init(Cipher.DECRYPT_MODE, k2, iv);
			FileInputStream is = new FileInputStream(input);
			FileOutputStream os = new FileOutputStream(output);
			
			byte[] buffer = new byte[64];
			int i;
			while((i=is.read(buffer))!=-1){
				byte[] ciphered = cipher.update(buffer, 0, i);
				if(ciphered!=null) {
					os.write(ciphered);
				}
			}
			byte[] lastCiphered = cipher.doFinal();
			if(lastCiphered!=null) {
				os.write(lastCiphered);
			}
			is.close();
			os.close();
		}
	public static void decrypt_rsa(File input, File output, PrivateKey pk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, pk);
		FileInputStream is = new FileInputStream(input);
		FileOutputStream os = new FileOutputStream(output);
		
		byte[] buffer = new byte[256];
		int i;
		while((i=is.read(buffer))!=-1){
			byte[] ciphered = cipher.doFinal(buffer);
			if(ciphered!=null) {
				os.write(ciphered);
			}
		}
		/*byte[] lastCiphered = cipher.doFinal();
		if(lastCiphered!=null) {
			os.write(lastCiphered);
		}*/
		is.close();
		os.close();
	}
	public static void encrypt_decrypt_hybrid(String filename) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		SecretKey key = generateKey(128);
		IvParameterSpec iv = generateIv();
		File input = new File(filename);
		File output = new File("encryptiontemp");
		File finalfile = new File("finalfile");
		KeyPair kp = keyPair_publicKey();
		byte[] secretKeyWrapped = encrypt_hybrid(key, iv, input, output, kp);
		decrypt_hybrid(key, iv, output, finalfile, kp, secretKeyWrapped);
	}
	
	public static void encrypt_decrypt_rsa(String filename) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {
		KeyPair kp = keyPair_publicKey();
		File input = new File(filename);
		File output = new File("encryptiontemp");
		File finalfile = new File("finalfile");
		encrypt_rsa(kp.getPublic(), input, output);
		decrypt_rsa(output, finalfile, kp.getPrivate());
	}
	
	public static KeyPair keyPair_publicKey() throws NoSuchAlgorithmException {
		KeyPairGenerator kg = KeyPairGenerator.getInstance(ALGORITHM);
		kg.initialize(2048);
		
		KeyPair generated_pair = kg.generateKeyPair();
		
		return generated_pair;
	}
	
	public static void main(String args[]) {
		Scanner sc = new Scanner(System.in);
		System.out.println("Filename: ");
		String filename = sc.nextLine();
		
		try {
			long startTime = System.currentTimeMillis();
			encrypt_decrypt_hybrid(filename);
			long stopTime = System.currentTimeMillis();
			float totalTime = (float)(stopTime-startTime)/1000;
			System.out.println("Hybrid in seconds: " + totalTime);
			startTime = System.currentTimeMillis();
			encrypt_decrypt_rsa(filename);
			stopTime = System.currentTimeMillis();
			totalTime = (float)(stopTime-startTime)/1000;
			System.out.println("Hybrid in seconds: " + totalTime);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
