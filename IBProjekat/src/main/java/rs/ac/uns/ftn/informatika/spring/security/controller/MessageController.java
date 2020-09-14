package rs.ac.uns.ftn.informatika.spring.security.controller;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.mail.MessagingException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import app.ReadMailClient;
import app.WriteMailClient;
import rs.ac.uns.ftn.informatika.spring.security.model.MessageDTO;
import rs.ac.uns.ftn.informatika.spring.security.model.Messages;
import rs.ac.uns.ftn.informatika.spring.security.model.User;
import rs.ac.uns.ftn.informatika.spring.security.model.UserRequest;
import rs.ac.uns.ftn.informatika.spring.security.service.UserService;
import xml.util.Util;

//Kontroler zaduzen za rad sa porukama
@RestController
@RequestMapping(value = "/api", produces = MediaType.APPLICATION_JSON_VALUE)
public class MessageController {

	@Autowired
	private UserService userService;
	
	@PostMapping(value = "/message/send")
	@PreAuthorize("hasRole('REGULAR')")
	public ResponseEntity<Map<String, String>> sendMessage(@RequestBody MessageDTO messageDTO) {
		
		System.out.println("\n\n\t----->Saljem poruku.<------------------");
		Map<String, String> result = new HashMap<>();
		String r="";
		
		try {
			Util.newMessage(messageDTO);
			r="The message was sent successfully!";
			result.put("r", r);
		} catch (Exception e) {
			r="Error sending message!";
			result.put("r", r);
			return ResponseEntity.badRequest().body(result);
		}
		return ResponseEntity.accepted().body(result);
	}
	
	@GetMapping("/message/all/{email}")
	@PreAuthorize("hasRole('REGULAR')")
	public Messages loadAllMessage(@PathVariable String email) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, IOException, MessagingException {
		Messages messages = Util.loadMessages(email);
		return messages;
	}
}
