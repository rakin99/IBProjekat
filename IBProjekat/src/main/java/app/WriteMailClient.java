package app;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;

import keystore.KeyStoreReader;
import rs.ac.uns.ftn.informatika.spring.security.model.MailBody;
import rs.ac.uns.ftn.informatika.spring.security.model.User;
import signature.SignatureManager;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
//	private static final String keyStoreFile = "./data/userb.jks";
//	private static final String keyStorePass = "0000";
//	private static final String keyStoreAlias = "pera";

	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	
	private static SignatureManager signatureManager = new SignatureManager();
	
	public static boolean sendMessage(String reciever,String subject,String body,User u) {
		
		System.out.println("Email of user: "+reciever);
		
		String keyStorePass = u.getUsername();
		String keyStoreAlias = reciever;
		String keyStoreFile = "./data/"+u.getUsername()+".jks";
		
		
        try {
        	Gmail service = getGmailService();
            
            //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            System.out.println("\n\ncompressedBody"+compressedBody);
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("DES"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher desCipherEnc = Cipher.getInstance("DES/ECB/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV(); //Nije potrebno
			desCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
			
			//sifrovanje
			byte[] ciphertext = desCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();  //Nije potrebno ali sam ga ostavio jer mi MailBody nije radilo kako treba.
			desCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
			
			byte[] ciphersubject = desCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
							
			// ucitavanje KeyStore fajla
			KeyStore keyStore = keyStoreReader.readKeyStore(keyStoreFile, keyStorePass.toCharArray());
				
			// preuzimanje sertifikata iz KeyStore-a za zeljeni alias
			Certificate certificate = keyStoreReader.getCertificateFromKeyStore(keyStore, keyStoreAlias);			
				
			// preuzimanje javnog kljuca iz ucitanog sertifikata
			PublicKey publicKey = keyStoreReader.getPublicKeyFromCertificate(certificate);
			System.out.println("\nProcitan javni kljuc iz sertifikata: " + publicKey);
			
			//preuzimanje privatnog kljuca
			PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keyStore, u.getUsername(), u.getUsername().toCharArray());
			
			//Potpisujemo digitalnim potpisom sadrzaj poruke
			byte[] signature = signatureManager.sign(compressedBody.getBytes(), privateKey);
			
			//kriptovanje poruke javnim kljucem
			Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			//inicijalizacija za kriptovanje, 
			//kod asimetricnog kriptuje se javnim kljucem, a dekriptuje privatnim
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, publicKey);
			
			//kriptovanje
			byte[] cipherSecretKey = rsaCipherEnc.doFinal(secretKey.getEncoded());
			System.out.println("cipherSecretKey: " + Base64.encodeToString(cipherSecretKey));
			
			
			//snimaju se bajtovi kljuca i IV.
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
//			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
//			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
			MailBody mailBody=new MailBody(ciphertext,ivParameterSpec1.getIV(),ivParameterSpec2.getIV(), cipherSecretKey,signature);
			String csv=mailBody.toCSV();
			
			System.out.println("---->"+ciphertextStr+"  "+csv);
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, ciphertextStr+"  "+csv);
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        	return true;
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
        return false;
	}
}
