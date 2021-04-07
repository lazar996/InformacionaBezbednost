package certificate;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

public class KeyStoreWriter {
	

		
		private KeyStore keyStore;
		
		public KeyStoreWriter() {
			try {
				keyStore = KeyStore.getInstance("JKS");
			} catch (KeyStoreException e) {
				e.printStackTrace();
			}
		}
		
		public void loadKeyStore(String fileName, char[] password) {
			try {
				if(fileName != null) 
					keyStore.load(new FileInputStream(fileName), password);
				else
					keyStore.load(null, password);
			
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		public void saveKeyStore(String fileName, char[] password) {
			try {
				keyStore.store(new FileOutputStream(fileName), password);
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		
		public void write(String alias, PrivateKey privateKey, char[] password, Certificate certificate) {
			try {
				keyStore.setKeyEntry(alias, privateKey, password, new Certificate[] {certificate});
			} catch (KeyStoreException e) {
				e.printStackTrace();
			}
		}
		
		public void testIt() {
			try {
				CertificateGenerator gen = new CertificateGenerator();
				KeyPair keyPair = gen.generateKeyPair();

				SimpleDateFormat iso8601Formater = new SimpleDateFormat("yyyy-MM-dd");
				Date startDate = iso8601Formater.parse("2007-12-31");
				Date endDate = iso8601Formater.parse("2017-12-31");
				
				X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
			    builder.addRDN(BCStyle.CN, "Lazar Djeric");
			    builder.addRDN(BCStyle.SURNAME, "Djeric");
			    builder.addRDN(BCStyle.GIVENNAME, "Lazar");
			    builder.addRDN(BCStyle.O, "BEZ-ORG");
			    builder.addRDN(BCStyle.OU, "student");
			    builder.addRDN(BCStyle.C, "RS");
			    builder.addRDN(BCStyle.E, "lazar@gmail.com");
			    builder.addRDN(BCStyle.UID, "123445");
			
				String sn="1";
				IssuerData issuerData = new IssuerData(keyPair.getPrivate(), builder.build());
				
				SubjectData subjectData = new SubjectData(keyPair.getPublic(), builder.build(), sn, startDate, endDate);
				X509Certificate cert = gen.generateCertificate(issuerData, subjectData);
				
				KeyStoreWriter keyStoreWriter = new KeyStoreWriter();
			
				keyStoreWriter.loadKeyStore(null, "ca10".toCharArray());
				keyStoreWriter.write("ca", keyPair.getPrivate(), "ca10".toCharArray(), cert);
				keyStoreWriter.saveKeyStore("./data/ca.jks", "ca10".toCharArray());
				
			} catch (ParseException e) {
				e.printStackTrace();
			}
		}
		
		public static void main(String[] args) {
			KeyStoreWriter keyStoreWriter = new KeyStoreWriter();
			keyStoreWriter.testIt();
		}

}
