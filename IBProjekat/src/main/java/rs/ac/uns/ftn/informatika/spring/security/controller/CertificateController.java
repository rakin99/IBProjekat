package rs.ac.uns.ftn.informatika.spring.security.controller;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import keystore.KeyStoreReader;
import keystore.KeyStoreWriter;
import rs.ac.uns.ftn.informatika.spring.security.model.IssuerData;
import rs.ac.uns.ftn.informatika.spring.security.model.SubjectData;
import rs.ac.uns.ftn.informatika.spring.security.model.User;
import rs.ac.uns.ftn.informatika.spring.security.service.UserService;


@RestController
@RequestMapping(value = "/api", produces = MediaType.APPLICATION_JSON_VALUE)
public class CertificateController {

	private static final String KEY_STORE_FILE = "./data/rakindejan@gmail.com.jks";
	private static final String KEY_STORE_PASS = "rakindejan@gmail.com";
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	private static KeyStoreWriter keyStoreWriter = new KeyStoreWriter();
	
	@Autowired
	private UserService userService;
	
	@GetMapping("/jks/{email}")
	@PreAuthorize("hasRole('REGULAR')")
	public KeyStore loadJks(@PathVariable String email) throws KeyStoreException {
		System.out.println("Get jks!");
		
		String keyStoreFile="./data/"+email+".jks";
		String keyStorePass=email;
		
		String alias=email;
		KeyStore keyStore = keyStoreReader.readKeyStore(keyStoreFile, keyStorePass.toCharArray());
		Certificate certificate = keyStoreReader.getCertificateFromKeyStore(keyStore, alias);
		PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keyStore, alias, alias.toCharArray());
		KeyStore keyStore2=keyStoreWriter.loadKeyStore(null, alias.toCharArray());
		keyStoreWriter.addToKeyStore(keyStore2, alias, privateKey, alias.toCharArray(), certificate);
		
		System.out.println("Alias: "+alias);
		System.out.println("\n\nPassword:"+alias.toCharArray());
		
		Certificate certificateRead = keyStoreReader.getCertificateFromKeyStore(keyStore2, alias);
		
		// preuzimanje NOVOG privatnog kljuca iz KeyStore-a za alias pod kojim smo ga upisali
		PrivateKey privateKeyRead = keyStoreReader.getPrivateKeyFromKeyStore(keyStore2, alias, alias.toCharArray());
		
		// preuzimanje podataka o izdavaocu NOVOG sertifikata
		IssuerData issuerDataRead = keyStoreReader.getIssuerFromCertificate(certificateRead, privateKeyRead);
		System.out.println("\nProcitani podaci o izdavacu sertifikata: " + issuerDataRead);
		
		// preuzimanje podataka o licu kojem je NOVI sertifikat izdat
		SubjectData subjectDataRead = keyStoreReader.getSubjectFromCertificate(certificateRead);
		System.out.println("Size: "+String.valueOf(keyStore.size()));
		System.out.println("\nProcitani podaci o licu kojem je sertifikat izdat: " + subjectDataRead);
		
		return keyStore;
	}
	
	@GetMapping("/certificate/{email}")
	@PreAuthorize("hasRole('REGULAR')")
	public String loadCertificate(@PathVariable String email) {
		
		String keyStoreFile=KEY_STORE_FILE;
		String keyStorePass=KEY_STORE_PASS;
		
		System.out.println("Get certificate!");
		User user=userService.findByEmail(email);
		String alias=email;
		KeyStore keyStore = keyStoreReader.readKeyStore(keyStoreFile, keyStorePass.toCharArray());
		Certificate certificate = keyStoreReader.getCertificateFromKeyStore(keyStore, alias);
		
		ObjectMapper myObjectMapper = new ObjectMapper();
		myObjectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		String testAString="";
		try {
			testAString = myObjectMapper.writeValueAsString(certificate);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		WriteObjectToFile(certificate, email);
		System.out.println("Tip: "+certificate.toString());
		
		return testAString;
	}
	
	public void WriteObjectToFile(Certificate cer,String email) {

		try {

			FileOutputStream fileOut = new FileOutputStream("C:\\Users\\Dejan\\git\\IBProjekat\\IBProjekat\\sertifikati\\"+email+".cer");
			ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
			objectOut.writeObject(cer.getEncoded());
			objectOut.close();
			fileOut.close();
			System.out.println("The Object  was succesfully written to a file");

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
}
