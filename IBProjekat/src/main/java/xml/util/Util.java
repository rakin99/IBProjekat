package xml.util;

import java.io.File;
import java.io.IOException;
import java.util.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.*;
import javax.xml.transform.dom.*;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

import rs.ac.uns.ftn.informatika.spring.security.model.MessageDTO;
import rs.ac.uns.ftn.informatika.spring.security.model.Messages;
import rs.ac.uns.ftn.informatika.spring.security.model.User;

import javax.xml.parsers.*;

public class Util {

	private static DocumentBuilderFactory builderFactory=DocumentBuilderFactory.newInstance();
	
	public static void newMessage(MessageDTO messageDTO) throws Exception {

		System.out.println("\nNova poruka");
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse("./data/poruke.xml");
        Element root = document.getDocumentElement();

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
    }
	
	public static Messages loadMessages(String primalac) {
		try {
			DocumentBuilder builder=builderFactory.newDocumentBuilder();
			Document document=builder.parse(new File("./data/poruke.xml"));
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
}
