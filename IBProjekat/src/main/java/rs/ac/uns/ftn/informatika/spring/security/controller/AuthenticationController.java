package rs.ac.uns.ftn.informatika.spring.security.controller;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import certificate.SignedCertificateGenerator;
import keystore.KeyStoreReader;
import keystore.KeyStoreWriter;
import rs.ac.uns.ftn.informatika.spring.security.model.IssuerData;
import rs.ac.uns.ftn.informatika.spring.security.model.SubjectData;
import rs.ac.uns.ftn.informatika.spring.security.model.User;
import rs.ac.uns.ftn.informatika.spring.security.model.UserRequest;
import rs.ac.uns.ftn.informatika.spring.security.model.UserTokenState;
import rs.ac.uns.ftn.informatika.spring.security.repository.UserRepository;
import rs.ac.uns.ftn.informatika.spring.security.security.TokenUtils;
import rs.ac.uns.ftn.informatika.spring.security.security.auth.JwtAuthenticationRequest;
import rs.ac.uns.ftn.informatika.spring.security.service.UserService;
import rs.ac.uns.ftn.informatika.spring.security.service.impl.CustomUserDetailsService;
import rs.ac.uns.ftn.informatika.spring.security.service.impl.UserServiceImpl;

// Kontroler zaduzen za autentifikaciju korisnika
@RestController
@RequestMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthenticationController {

	private static KeyStoreWriter keyStoreWriter = new KeyStoreWriter();
	private static final String KEY_STORE_FILE = "./data/test.jks";
	private static final String KEY_STORE_PASS = "test10";
	private static final String KEY_STORE_ALIAS = "test";
	private static final String KEY_STORE_PASS_FOR_PRIVATE_KEY = "test10";
	private static SignedCertificateGenerator signedCertificateGenerator = new SignedCertificateGenerator();
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	
	@Autowired
	private TokenUtils tokenUtils;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	@Autowired
	private UserService userService;
	
	@Autowired
	private UserServiceImpl userServiceImpl;
	
	@Autowired
	private UserRepository userRepository;

	// Prvi endpoint koji pogadja korisnik kada se loguje.
	// Tada zna samo svoje korisnicko ime i lozinku i to prosledjuje na backend.
	@PostMapping("/login")
	public ResponseEntity<UserTokenState> createAuthenticationToken(@RequestBody JwtAuthenticationRequest authenticationRequest,
			HttpServletResponse response) {

		
		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
						authenticationRequest.getPassword()));

		// Ubaci korisnika u trenutni security kontekst
		SecurityContextHolder.getContext().setAuthentication(authentication);

		// Kreiraj token za tog korisnika
		User user = (User) authentication.getPrincipal();
		String jwt = tokenUtils.generateToken(user.getUsername(), user.getAuthoritiesAsString());
		int expiresIn = tokenUtils.getExpiredIn();

		// Vrati token kao odgovor na uspesnu autentifikaciju
		return ResponseEntity.ok(new UserTokenState(jwt, expiresIn));
	}

	// Endpoint za registraciju novog korisnika
	@PostMapping("/signup")
	public ResponseEntity<Map<String, String>> addUser(@RequestBody UserRequest userRequest, UriComponentsBuilder ucBuilder) throws AddressException {

		Map<String, String> result = new HashMap<>();
		String r="";
		User existUser = this.userService.findByEmail(userRequest.getEmail());
		if (existUser != null) {
			r="E-mail already exists!";
			result.put("result", "error");
			result.put("r", r);
			return ResponseEntity.badRequest().body(result);
		}
		if (!isValidEmailAddress(userRequest.getEmail())) {
			r="E-mail address is not valid!";
			result.put("result", "error");
			result.put("r", r);
			return ResponseEntity.badRequest().body(result);
		}else {
			r="You have successfully registered!";
			User user = this.userServiceImpl.save(userRequest);
			UserRequest u=new UserRequest(user);
			createCertificate(u);
			user.setCertificate("./data/"+u.getEmail()+".cer");
			User user2=  this.userRepository.save(user);
			System.out.println(user2.toString());
			HttpHeaders headers = new HttpHeaders();
			headers.setLocation(ucBuilder.path("/api/user/{userId}").buildAndExpand(user.getId()).toUri());
			result.put("r", r);
			result.put("result", "success");
		}
		
		return ResponseEntity.accepted().body(result);
	}

	// U slucaju isteka vazenja JWT tokena, endpoint koji se poziva da se token osvezi
	@PostMapping(value = "/refresh")
	public ResponseEntity<?> refreshAuthenticationToken(HttpServletRequest request) {

		String token = tokenUtils.getToken(request);
		String email = this.tokenUtils.getEmailFromToken(token);
		User user = (User) this.userDetailsService.loadUserByUsername(email);

		if (this.tokenUtils.canTokenBeRefreshed(token, user.getLastPasswordResetDate())) {
			String refreshedToken = tokenUtils.refreshToken(token);
			int expiresIn = tokenUtils.getExpiredIn();

			return ResponseEntity.ok(new UserTokenState(refreshedToken, expiresIn));
		} else {
			UserTokenState userTokenState = new UserTokenState();
			return ResponseEntity.badRequest().body(userTokenState);
		}
	}

	@RequestMapping(value = "/change-password", method = RequestMethod.POST)
	@PreAuthorize("hasRole('REGULAR')")
	public ResponseEntity<?> changePassword(@RequestBody PasswordChanger passwordChanger) {
		userDetailsService.changePassword(passwordChanger.oldPassword, passwordChanger.newPassword);

		Map<String, String> result = new HashMap<>();
		result.put("result", "success");
		return ResponseEntity.accepted().body(result);
	}

	static class PasswordChanger {
		public String oldPassword;
		public String newPassword;
	}
	
	@RequestMapping(value = "/activate", method = RequestMethod.POST)
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> activate(@RequestBody UserRequest userRequest) {
		System.out.println("U activate sam!");
		User existUser = this.userService.findByEmail(userRequest.getEmail());
		existUser.setEnabled(userRequest.isActive());
		
		User user=userRepository.save(existUser);
		
		Map<String, String> result = new HashMap<>();
		result.put("result", "success");
		return ResponseEntity.accepted().body(result);
	}
	
	public static boolean isValidEmailAddress(String email) {
        boolean result = true;
        try {
            InternetAddress emailAddr = new InternetAddress(email);
            emailAddr.validate();
        } catch (AddressException ex) {
            result = false;
        }
        return result;
    }
	
	private static void createCertificate(UserRequest userRequest) {
		System.out.println("\n<<<<< Generisanje Signed sertifikata >>>>>\n");
		
		//	####### SUBJECT DATA #######
		
		// generisemo par kljuceva za vlasnika sertifikata (privatni i javni kljuc)
		KeyPair keyPair = signedCertificateGenerator.generateKeyPair();
		
		String ime="User"+userRequest.getId();
		String prezime="User"+userRequest.getId();
		String imeIPrezime=ime+" "+prezime;
		
		// osnovni podaci o vlasniku sertifikata
		X500Name X500NameSubject = signedCertificateGenerator.generateX509Name(imeIPrezime, prezime, ime, "FTN", "UNS", "RS", userRequest.getEmail(), String.valueOf(userRequest.getId()));
		
		// postavljanje datuma vazenja sertifikata
		Date startDate, endDate = null;
		Calendar calendar = GregorianCalendar.getInstance();
		startDate = calendar.getTime(); // sertifikat vazi od trenutnog vremena (datum kreiranja sertifikata)
		calendar.setTime(startDate);
		calendar.add(GregorianCalendar.YEAR, 2); // sertifikat traje 2 godine od datuma kreiranja
		endDate = calendar.getTime();
		
		// serijski broj sertifikata
		String serialNumber = String.valueOf(userRequest.getId()+1);
		
		// kreiranje objekta koji sadrzi sve potrebne informacije o za vlasnika sertifikata
		SubjectData subjectData = new SubjectData(keyPair.getPublic(), X500NameSubject, serialNumber, startDate, endDate);
		
		// ######################################################
		
		
		// ####### ISSUER DATA #######
		
		// podaci o izdavacu sertifikata se citaju iz KeyStore-a:
		// KeyStore: test.jks; Sifra za otvaranje: test10; Alias za sertifikat i javni kljuc: test; sifra za privatni kljuc: test10
		
		// ucitavanje KeyStore fajla
		KeyStore keyStore = keyStoreReader.readKeyStore(KEY_STORE_FILE, KEY_STORE_PASS.toCharArray());
				
		// preuzimanje sertifikata izdavaca sertifikata iz KeyStore-a za zeljeni alias
		Certificate issuerCertificate = keyStoreReader.getCertificateFromKeyStore(keyStore, KEY_STORE_ALIAS);
		
		// preuzimanje privatnog kljuca iz KeyStore-a za zeljeni alias
		PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keyStore, KEY_STORE_ALIAS, KEY_STORE_PASS_FOR_PRIVATE_KEY.toCharArray());
		
		// preuzimanje podataka o izdavaocu sertifikata
		IssuerData issuerData = keyStoreReader.getIssuerFromCertificate(issuerCertificate, privateKey);
				
		// ######################################################
		
		
		// ####### KREIRANJE POTPISANOG SERTIFIKATA I UPISIVANJE U KEYSTORE #######
		
		X509Certificate signedCertificate = signedCertificateGenerator.generateSignedCertificate(issuerData, subjectData);
		
		// upisivanje NOVOG potpisanog sertifikata u KeyStore:
		// KeyStore: test.jks; Sifra za otvaranje: test10; Alias za novi sertifikat i javni kljuc: pera; sifra za privatni kljuc: pera
		
		String alias=userRequest.getEmail();
		
		System.out.println("Alias: "+alias);
		
		// upisivanje u KeyStore, dodaju se kljuc i sertifikat
		keyStoreWriter.addToKeyStore(keyStore, alias, keyPair.getPrivate(), alias.toCharArray(), signedCertificate);
		
		// cuvanje izmena na disku
		keyStoreWriter.saveKeyStore(keyStore, KEY_STORE_FILE, KEY_STORE_PASS.toCharArray());
		
		// ######################################################
		
		
		// ####### CITANJE POTPISANOG SERTIFIKATA IZ KEYSTORE #######
		
		// po uzoru na primer4, koristi se KeyStoreReader klasa za citanje novog sertifikata i novog privatnog kljuca koji su
		// programski upisani u KeyStore ...
		// KeyStore: test.jks; Sifra za otvaranje: test10; Alias za novi sertifikat i javni kljuc: pera; sifra za privatni kljuc: pera
		
		// preuzimanje NOVOG sertifikata iz KeyStore-a za alias pod kojim smo ga upisali
		Certificate certificateRead = keyStoreReader.getCertificateFromKeyStore(keyStore, alias);
		
		// preuzimanje NOVOG privatnog kljuca iz KeyStore-a za alias pod kojim smo ga upisali
		PrivateKey privateKeyRead = keyStoreReader.getPrivateKeyFromKeyStore(keyStore, alias, alias.toCharArray());
		
		// preuzimanje podataka o izdavaocu NOVOG sertifikata
		IssuerData issuerDataRead = keyStoreReader.getIssuerFromCertificate(certificateRead, privateKeyRead);
		System.out.println("\nProcitani podaci o izdavacu sertifikata: " + issuerDataRead);
		
		// preuzimanje podataka o licu kojem je NOVI sertifikat izdat
		SubjectData subjectDataRead = keyStoreReader.getSubjectFromCertificate(certificateRead);
		System.out.println("\nProcitani podaci o licu kojem je sertifikat izdat: " + subjectDataRead);
		
		// ######################################################
		
		
		// ####### VALIDACIJA SERTIFIKATA ####### 
		
		// uspesna validacija sertifikata - validacija sa javnim kljucem izdavaca sertifikata!	
		validateCertificate((X509Certificate) certificateRead, keyStoreReader.getPublicKeyFromCertificate(issuerCertificate));
	}
	
	/**
	 * Metoda koja sluzi za proveru da li je sertifikat ispravan.
	 * 
	 * @param certificate - Sertifikat koji se validira
	 * @param publicKey - javni kljuc koji se vrsi validacija sertifikata
	 * 
	 * Sertifikat se potpisuje privatnim kljucem izdavaca. Sertifikat jedino uspeÅ¡no moÅ¾e da se validira javnim kljucem izdavaca!
	 */
	private static boolean validateCertificate(X509Certificate certificate, PublicKey publicKey) {
	
		// ako validacija nije uspesna desice se exception
		try {
			certificate.verify(publicKey);
			System.out.println("\nVALIDACIJA SERTIFIKATA USPESNA!");
			return true;
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			System.out.println("\nVALIDACIJA SERTIFIKATA NIJE USPESNA!");
			return false;
		}
	}
}