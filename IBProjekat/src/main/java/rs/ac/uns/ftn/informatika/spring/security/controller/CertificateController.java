package rs.ac.uns.ftn.informatika.spring.security.controller;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.xml.bind.DatatypeConverter;

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

	private static final String KEY_STORE_FILE = "./data/test.jks";
	private static final String KEY_STORE_PASS = "test10";
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	private static KeyStoreWriter keyStoreWriter = new KeyStoreWriter();
	
	@Autowired
	private UserService userService;
	
	@GetMapping("/jks/{email}")
	@PreAuthorize("hasRole('REGULAR')")
	public boolean loadJks(@PathVariable String email) throws KeyStoreException, FileNotFoundException {
System.out.println("Get jks!");
		
		String keyStoreFile="./data/test.jks";
		String keyStorePass="test10";
		
		String alias=email;
		KeyStore keyStore = keyStoreReader.readKeyStore(keyStoreFile, keyStorePass.toCharArray());
		Certificate certificate = keyStoreReader.getCertificateFromKeyStore(keyStore, alias);
		PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keyStore, alias, alias.toCharArray());
		KeyStore keyStore2=keyStoreWriter.loadKeyStore(null, alias.toCharArray());
		keyStoreWriter.addToKeyStore(keyStore2, alias, privateKey, alias.toCharArray(), certificate);

		ObjectMapper myObjectMapper = new ObjectMapper();
		myObjectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		
		keyStoreWriter.saveKeyStore(keyStore2, "C:\\Users\\Dejan\\Downloads\\"+alias+".jks", alias.toCharArray());
	
		return true;
	}
	
	@GetMapping(value = "/certificate/{email}")
	@PreAuthorize("hasRole('REGULAR')")
	public String loadCertificate(@PathVariable String email) throws IOException {
		
		String keyStoreFile=KEY_STORE_FILE;
		String keyStorePass=KEY_STORE_PASS;
		
		System.out.println("Get certificate!");
		User user=userService.findByEmail(email);
		String alias=email;
		KeyStore keyStore = keyStoreReader.readKeyStore(keyStoreFile, keyStorePass.toCharArray());
		Certificate certificate = keyStoreReader.getCertificateFromKeyStore(keyStore, alias);
		
		ObjectMapper myObjectMapper = new ObjectMapper();
		myObjectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		
		String certificateStr = certToString(certificate); 
		
		String testAString="";
		try {
			testAString = myObjectMapper.writeValueAsString(certificateStr);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		//WriteObjectToFile(certificate, email);
		
//		FileWriter fw = new FileWriter("C:\\Users\\Dejan\\git\\IBProjekat\\IBProjekat\\sertifikati\\"+email+".cer");
//		fw.write(certToString(certificate));
//		fw.close();
		
		System.out.println("Sertifikat: "+testAString);
		return testAString;
	}
	
	public static String certToString(Certificate cert) {
		StringWriter sw = new StringWriter();
		try {
			sw.write("-----BEGIN CERTIFICATE-----\n");
			sw.write(DatatypeConverter.printBase64Binary(cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
			sw.write("\n-----END CERTIFICATE-----\n");
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		return sw.toString();
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
