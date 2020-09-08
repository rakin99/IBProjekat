package rs.ac.uns.ftn.informatika.spring.security.controller;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
	public KeyStore loadJks(@PathVariable String email) {
		System.out.println("Get jks!");
		User user=userService.findByEmail(email);
		String alias="user"+user.getId();
		KeyStore keyStore = keyStoreReader.readKeyStore(KEY_STORE_FILE, KEY_STORE_PASS.toCharArray());
		Certificate certificate = keyStoreReader.getCertificateFromKeyStore(keyStore, alias);
		PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keyStore, alias, alias.toCharArray());
		KeyStore keyStore2=keyStoreWriter.loadKeyStore(null, alias.toCharArray());
		keyStoreWriter.addToKeyStore(keyStore2, alias, privateKey, alias.toCharArray(), certificate);
		
		Certificate certificateRead = keyStoreReader.getCertificateFromKeyStore(keyStore2, alias);
		
		// preuzimanje NOVOG privatnog kljuca iz KeyStore-a za alias pod kojim smo ga upisali
		PrivateKey privateKeyRead = keyStoreReader.getPrivateKeyFromKeyStore(keyStore2, alias, alias.toCharArray());
		
		// preuzimanje podataka o izdavaocu NOVOG sertifikata
		IssuerData issuerDataRead = keyStoreReader.getIssuerFromCertificate(certificateRead, privateKeyRead);
		System.out.println("\nProcitani podaci o izdavacu sertifikata: " + issuerDataRead);
		
		// preuzimanje podataka o licu kojem je NOVI sertifikat izdat
		SubjectData subjectDataRead = keyStoreReader.getSubjectFromCertificate(certificateRead);
		System.out.println("\nProcitani podaci o licu kojem je sertifikat izdat: " + subjectDataRead);
		
		return keyStore;
	}
	
	@GetMapping("/certificate/{email}")
	@PreAuthorize("hasRole('REGULAR')")
	public Certificate loadCertificate(@PathVariable String email) {
		System.out.println("Get certificate!");
		User user=userService.findByEmail(email);
		String alias="user"+user.getId();
		KeyStore keyStore = keyStoreReader.readKeyStore(KEY_STORE_FILE, KEY_STORE_PASS.toCharArray());
		Certificate certificate = keyStoreReader.getCertificateFromKeyStore(keyStore, alias);
		PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keyStore, alias, alias.toCharArray());
		KeyStore keyStore2=keyStoreWriter.loadKeyStore(null, alias.toCharArray());
		keyStoreWriter.addToKeyStore(keyStore2, alias, privateKey, alias.toCharArray(), certificate);
		
		Certificate certificateRead = keyStoreReader.getCertificateFromKeyStore(keyStore2, alias);
		
		System.out.println("Tip: "+certificateRead.getType());
		
		return certificateRead;
	}
	
}
