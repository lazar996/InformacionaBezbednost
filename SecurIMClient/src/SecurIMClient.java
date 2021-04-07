import java.io.ByteArrayInputStream;
import java.io.File;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URI;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import certificate.CertificateReader;
import encrypt.DecryptKEK;
import signature.ProveraPotpisa;
import signature.VerifySignatureEnveloped;

public class SecurIMClient {

	
	private static final String IN_FILE =  "./data/messageEnveloped.xml";
	private static final String IN_FILE1 =  "./data/message_on.xml";
	private static final String OUT_FILE = "./data/message_on.xml";
	private static final String IN_FILE_CERTIFICATE = "./data/usera_Lazar.cer";
	
	public static DecryptKEK decryptKEK= new DecryptKEK();
	public static ProveraPotpisa proveraPotpisa= new ProveraPotpisa();
	public static VerifySignatureEnveloped verifySignatureEnveloped= new VerifySignatureEnveloped();
	public static CertificateReader certificateReader= new CertificateReader();
	
	
	public static void main(String[] args) throws TransformerException {
		
		
		//primer slanja poruke
		Document message = loadDocument(IN_FILE);
		try {
	
			post(message);
			
			System.out.println("test0");
		} catch (UniformInterfaceException | ClientHandlerException
				| TransformerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("test1");}
		//primer preuzimanja svih poruka
		Document doc =null;
		Integer i = 1;	
	
		while ((doc = get("goran", i.toString())) != null) {
			System.out.println("");
			System.out.println("Poruka: ");
			System.out.println("");
			System.out.println(doc2string(doc));	
			saveDocument(doc, OUT_FILE);
			Document doc1 = loadDocument(IN_FILE1);
			System.out.println("");
			System.out.println("provera digitalnog potpisa: ");
			//proverva se digitalni potpis
			proveraPotpisa.testIt(doc1);
			System.out.println("");
			System.out.println("citanje sertifikata: ");
			//citanje sertifikate
			certificateReader.testIt(IN_FILE_CERTIFICATE);	
			System.out.println("");
			System.out.println("provera sertifikata:");
			//provera sertifikata
			verifySignatureEnveloped.testIt(doc1);
			System.out.println("");
			System.out.println("");
		
			//ispis porukue
			decryptKEK.testIt(doc1);
			
			i++;
				
			
		}
		
	
		
	}
	
	public static void provera() {
		

		
	}
	
	public static void saveDocument(Document doc, String fileName) {
		try {
			File outFile = new File(fileName);
			FileOutputStream f = new FileOutputStream(outFile);

			TransformerFactory factory = TransformerFactory.newInstance();
			Transformer transformer = factory.newTransformer();
			
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(f);
			
			transformer.transform(source, result);

			f.close();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (TransformerFactoryConfigurationError e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	
	private static URI getBaseURI() {
		return UriBuilder.fromUri("http://localhost:8080/SecurIM").build();
	}

	public static Document get(String userId, String messageid) {
		
		ClientConfig config = new DefaultClientConfig();
		Client client = Client.create(config);
		String message = null;
		WebResource service = client.resource(getBaseURI());
		try {
			message = service.path("messages").path(userId).path(messageid)
					.accept(MediaType.TEXT_PLAIN).get(String.class);
		} catch (Exception ex) {
			return null;
		}
		if (message != null) {

			return string2Doc(message);

		}
		return null;

	}

	public static void post(Document doc) throws UniformInterfaceException,
			ClientHandlerException, TransformerException {
		ClientConfig config = new DefaultClientConfig();
		Client client = Client.create(config);
		WebResource service = client.resource(getBaseURI());

		service.path("messages").accept(MediaType.TEXT_PLAIN)
				.post(doc2string(doc));
	}

	private static String doc2string(Document doc) throws TransformerException {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		String output = writer.getBuffer().toString();

		return output;
	}

	private static Document string2Doc(String string) {

		Document document = null;

		try {
			document = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder()
					.parse(new ByteArrayInputStream(string.getBytes()));
		} catch (SAXException | IOException | ParserConfigurationException e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
		}
		return document;
	}
	
	
	private static Document loadDocument(String file) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document document = db.parse(file);
			
			return document;
		} catch (FactoryConfigurationError e) {
			e.printStackTrace();
			return null;
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
			return null;
		} catch (SAXException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
}
