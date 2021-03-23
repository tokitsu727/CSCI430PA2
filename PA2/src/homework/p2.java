package homework;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class p2 {
	public static final String ALGORITHM = "RSA";
	
	public static KeyPair genKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator kg = KeyPairGenerator.getInstance(ALGORITHM);
		kg.initialize(512);
		
		KeyPair generated_pair = kg.generateKeyPair();
		
		return generated_pair;
	}
	
	public static byte[] sign(PrivateKey privateKey, String address) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException {
		Signature dsa = Signature.getInstance("SHA256withRSA");
		dsa.initSign(privateKey);
		
		FileInputStream fis = new FileInputStream(address);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		
		while ((len = bufin.read(buffer))>=0) {
			dsa.update(buffer,0,len);
		}
		bufin.close();
		
		byte[] signature = dsa.sign();
		return signature;
	}
	
	public static boolean verify(String publicKeyS, String signatureS, String address) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, InvalidKeySpecException {
		byte[] publicKeyB = Base64.getDecoder().decode(publicKeyS);
		byte[] signature = Base64.getDecoder().decode(signatureS);
		PublicKey publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(publicKeyB));
		
		Signature dsa = Signature.getInstance("SHA256withRSA");
		dsa.initVerify(publicKey);
		
		FileInputStream fis = new FileInputStream(address);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		
		while ((len = bufin.read(buffer))>=0) {
			dsa.update(buffer,0,len);
		}
		bufin.close();
		
		return dsa.verify(signature);
		
	}
	
	public static void main(String args[]) {
		Scanner sc = new Scanner(System.in);
		System.out.println("Sign/Verify");
		String uin = sc.nextLine().toLowerCase();
		if(uin.equals("sign")) {
			try {
				System.out.print("Filename: ");
				uin = sc.nextLine();
				KeyPair kp = genKeyPair();
				PrivateKey privateKey = kp.getPrivate();
				byte[] signature = sign(privateKey, uin);
				String signatureS = Base64.getEncoder().encodeToString(signature);
				String privateKeyS = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
				System.out.println("Signature: " + signatureS);
				System.out.println("Public Key: " + privateKeyS);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else if(uin.equals("verify")) {
			try {
				System.out.print("Filename: ");
				String filename = sc.nextLine();
				System.out.print("Public Key: ");
				String pubkey = sc.nextLine();
				System.out.print("Signature: ");
				String signature = sc.nextLine();
				if(verify(pubkey, signature, filename)) {
					System.out.println("Verification Success");
				} else {
					System.out.println("Verification fail");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
