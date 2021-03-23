package homework;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
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
class InvalidLedgerException extends Exception{
	public InvalidLedgerException(String message) {
		super(message);
	}
}
public class P3 {
	public static final String ALGORITHM = "RSA";
	public static final String HASH_ALGORITHM = "SHA-256";
	private static String global_filename = null;
	public static void writeTo(String filename, String data) throws IOException {
		FileWriter fw = new FileWriter(filename, true);
		fw.write(data + "\n");
		fw.close();
	}
	
	public static String writeLedger(String filename, String data, String priorLine) throws IOException, NoSuchAlgorithmException{
		String hashPointerString = "";
		if(priorLine != null) {
			hashPointerString = Base64.getEncoder().encodeToString(hash(priorLine));
		}
		String stringToAdd = data + hashPointerString;
		writeTo(filename, stringToAdd);
		return stringToAdd;
	}
	
	public static byte[] hash(String data) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
		byte[] encoded = md.digest(data.getBytes());
		
		return encoded;
	}
	
	public static boolean hash_compare(String data, byte[] hash) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		byte[] encoded = hash(data);
		return MessageDigest.isEqual(encoded, hash);
	}
	
	//Returns final line read
	public static String process(String filename) throws  IOException, NoSuchAlgorithmException, InvalidLedgerException {
		try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
		    String line;
		    String lastline;
		    byte[] currentHashPointer = null;
		    //Read First Line, or attempt to
		    if ((line=br.readLine())!= null){
		    	currentHashPointer = hash(line);
		    }
		    lastline = line;
		    while ((line = br.readLine()) != null) {
		    	
		       String data = line.substring(0,8);
		       String hashPointer = line.substring(8);
		       
		       //currentHashPointer contains hash of previous line
		       //data is the data of current line (irrelevant)
		       
		       //Check if hashpointer stored in ledger is equal to the one obtained from previous block
		       if(!hashPointer.equals(Base64.getEncoder().encodeToString(currentHashPointer))) {
		    	   throw new InvalidLedgerException("Ledger has been modified");
		       }
		       currentHashPointer = hash(line);
		       lastline=line;
		    }
		    
		    if(!compare_finalHashPointer(Base64.getEncoder().encodeToString(hash(lastline)))) {
		    	throw new InvalidLedgerException("Ledger has been modified");
		    }

		    return lastline;
		} catch (FileNotFoundException e) {
			//If no such file exists, we will create one. 
			File newLedger = new File(filename);
			newLedger.createNewFile();
			return null;
		}
	}
	
	public static void userInput() throws FileNotFoundException, NoSuchAlgorithmException, IOException, InvalidLedgerException {
		Scanner sc = new Scanner(System.in);
		//Process file
		System.out.println("Input Filename: ");
		String filename = sc.nextLine();
		global_filename=filename;
		String finalLine = process(filename);
		//Stores last line so we don't have to read it.
		
	
		//If we got this far, there's no issues with the ledger.
		
		boolean done = false;
		while(!done) {
			System.out.println("Input/Done");
			String uin = sc.nextLine().toLowerCase();
			if(uin.equals("done")) {
				done = true;
			} else if(uin.contentEquals("input")) {
				//Add a line to the file.
				uin = sc.nextLine();
				if (uin.length() != 8) {
					System.out.println("Input must be of length 8");
				} else {
					finalLine = writeLedger(filename, sc.nextLine(), finalLine);
				}
			} else {
				System.out.println("Must be one or the other.");
			}
		}
		
		//Store final hashpointer in its own file.
		store_finalHashPointer(Base64.getEncoder().encodeToString(hash(finalLine)));
	}
	
	public static void store_finalHashPointer(String finalHash) throws IOException {
		String build_filename = "finalhashptr" + global_filename;
		File finalhashfile = new File(build_filename);
		finalhashfile.createNewFile();
		FileWriter fw = new FileWriter(finalhashfile, false);
		fw.write(finalHash);
		fw.close();
	}
	
	public static boolean compare_finalHashPointer(String lineHash) throws FileNotFoundException, IOException {
		String build_filename = "finalhashptr" + global_filename;
		try (BufferedReader br = new BufferedReader(new FileReader(build_filename))) {
			String line;
			if((line=br.readLine())!= null){
				return line.equals(lineHash);
			}
			return false;
		} catch (FileNotFoundException e) {
			return false;
		}
	}
	
	public static void main(String args[]) {
		System.out.println("Using UTF-8 encoding, 8 byte long values.");
		System.out.println("Input 8 byte Strings (8 characters in UTF-8)");
		System.out.println("Filename should just be the filename, it will go into the main folder.(eg. example.txt, not src/example.txt)");
		//Notes about execution:
		//If ledger exists but a finalhashptr file for the ledger does not, execution will be denied.
		//If ledger does not exist, a ledger file will be created.
		
		try {
			userInput();
		} catch (NoSuchAlgorithmException | IOException | InvalidLedgerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
}
