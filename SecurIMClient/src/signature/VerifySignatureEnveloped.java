package signature;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.implementations.RSAKeyValueResolver;
import org.apache.xml.security.keys.keyresolver.implementations.X509CertificateResolver;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


public class VerifySignatureEnveloped {

	
    static {
        Security.addProvider(new BouncyCastleProvider());
        org.apache.xml.security.Init.init();
    }
	
	public boolean testIt(Document doc) {
		boolean res = verifySignature(doc);
		System.out.println("Verification = " + res);
		return res;
	}
	

	private boolean verifySignature(Document doc) {
		
		try {

			NodeList signatures = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
			Element signatureEl = (Element) signatures.item(0);
			
			Node sender =  doc.getElementsByTagName("senderId").item(0);
			Element senderId = (Element) sender;
			String senderID = senderId.getTextContent();
			XMLSignature signature = new XMLSignature(signatureEl, null);
			KeyInfo keyInfo = signature.getKeyInfo();
			if(keyInfo != null) {
				
				keyInfo.registerInternalKeyResolver(new RSAKeyValueResolver());
			    keyInfo.registerInternalKeyResolver(new X509CertificateResolver());
			    
			    if(keyInfo.containsX509Data() && keyInfo.itemX509Data(0).containsCertificate()) { 
			        Certificate cert = keyInfo.itemX509Data(0).itemCertificate(0).getX509Certificate();
			        
			        if( (senderID.equals("pera"))){
			        	if(cert != null) {
			        		if(senderID.equals("pera")){
			        			KeyStore ks = null;
			        			try {
			        				char[] password = "usera".toCharArray();
			        				String KEY_STORE_FILE = "./data/usera.jks"; 
			        				ks = KeyStore.getInstance("JKS", "SUN");
			        				BufferedInputStream in = new BufferedInputStream(new FileInputStream(KEY_STORE_FILE));
			        				ks.load(in, password);
			        				System.out.println("Cita se Sertifikat i privatni kljuc CA...");
			        				
			        				if(ks.isKeyEntry("usera")) {
			        					X509Certificate cert2 = (X509Certificate) ks.getCertificate("usera");
			        					X500Name name = new JcaX509CertificateHolder(cert2).getSubject();
			        					RDN n = name.getRDNs(BCStyle.CN)[0];
			        					System.out.println(n.getFirst().getValue());
			        					if(n.getFirst().getValue().toString().trim().equals("usera")){
			        						return signature.checkSignatureValue((X509Certificate) cert);
			        					}else{
			        						return false;
			        					}
			        				}
			        				else
			        					System.out.println("Nema para kljuceva za CA");
			        			} catch (KeyStoreException e) {
			        				e.printStackTrace();
			        			} catch (NoSuchProviderException e) {
			        				e.printStackTrace();
			        			} catch (FileNotFoundException e) {
			        				e.printStackTrace();
			        			} catch (NoSuchAlgorithmException e) {
			        				e.printStackTrace();
			        			} catch (CertificateException e) {
			        				e.printStackTrace();
			        			} catch (IOException e) {
			        				e.printStackTrace();
			        			}
			        		}
			        	}
			        }
			        else if( !(senderID.equals("usera")) ){
			        	System.out.println("Neregularna poruka - pogresan sertifikat!");
			        	
			        	return false;
			        }
			        
			        else
			        	return false;
			    }
			    else
			    	return false;
			}
			else
				return false;

		
		} catch (XMLSignatureException e) {
			e.printStackTrace();
			return false;
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			return false;
		}
		return false;
	}
	
	
	
}
