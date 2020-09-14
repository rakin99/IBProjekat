package xml.util;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.*;
import javax.xml.transform.dom.*;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

import keystore.KeyStoreReader;
import rs.ac.uns.ftn.informatika.spring.security.model.MessageDTO;
import rs.ac.uns.ftn.informatika.spring.security.model.Messages;
import rs.ac.uns.ftn.informatika.spring.security.model.User;
import xml.signature.SignEnveloped;
import xml.signature.VerifySignatureEnveloped;

import javax.xml.parsers.*;

public class Util {

	private static DocumentBuilderFactory builderFactory=DocumentBuilderFactory.newInstance();
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	
	public static void newMessage(MessageDTO messageDTO) throws Exception {

		String posiljaoc=messageDTO.getSender();
		String primalac=messageDTO.getEmailAddress();
		
		System.out.println("Posiljaoc: "+posiljaoc);
		System.out.println("Primalac: "+primalac);
		String keyStorePass = posiljaoc;
		String keyStoreAlias = primalac;
		String keyStoreFile = "./data/"+posiljaoc+".jks";
		
		System.out.println("\nNova poruka");
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse("./data/poruke.xml");
        Element root = document.getDocumentElement();

        NodeList nodeList1=root.getElementsByTagName("poruka");
        NodeList nodeList2=root.getElementsByTagName("ds:Signature");
        removeAll(nodeList1, root);
        removeAll(nodeList2, root);
        
        List<MessageDTO> messages = new ArrayList<MessageDTO>();
        messages.add(new MessageDTO());

        for (MessageDTO m : messages) {
            // server elements
            Element newMessage = document.createElement("poruka");

            newMessage.setAttribute("posiljaoc", messageDTO.getSender());
            newMessage.setAttribute("primalac", messageDTO.getEmailAddress());
            
            Element subject = document.createElement("subject");
            subject.appendChild(document.createTextNode(messageDTO.getSubject()));
            newMessage.appendChild(subject);
            
            Element body = document.createElement("body");
            body.appendChild(document.createTextNode(messageDTO.getContent()));
            newMessage.appendChild(body);

            root.appendChild(newMessage);
        }

        DOMSource source = new DOMSource(document);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        StreamResult result = new StreamResult("./data/poruke.xml");
        transformer.transform(source, result);
        
        // ucitavanje KeyStore fajla
        KeyStore keyStore = keyStoreReader.readKeyStore(keyStoreFile, keyStorePass.toCharArray());
     
        // preuzimanje sertifikata iz KeyStore-a za zeljeni alias
		Certificate certificateSignature = keyStoreReader.getCertificateFromKeyStore(keyStore, posiljaoc);
		
		//preuzimanje privatnog kljuca
		PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keyStore, messageDTO.getSender(), messageDTO.getSender().toCharArray());
        
		SignEnveloped sign = new SignEnveloped();
        sign.testIt("./data/poruke.xml",privateKey,certificateSignature,"./data/poruke.xml");
    }
	
	public static Messages loadMessages(String primalac) {
		try {
			DocumentBuilder builder=builderFactory.newDocumentBuilder();
			Document document=builder.parse(new File("./data/poruke.xml"));
			VerifySignatureEnveloped verify = new VerifySignatureEnveloped();
			verify.testIt("./data/poruke.xml");
			Node node=document.getElementsByTagName("poruke").item(0);
			Messages messages=Messages.loadFromDom(node,primalac);
			System.out.println(messages);
			
			return messages;
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static void removeAll(NodeList nodeList,Element root) 
    {
        for(int i=0; i<nodeList.getLength(); i++)
        {
        	Node n=nodeList.item(i);
        	root.removeChild(n);
        }
    }
}
