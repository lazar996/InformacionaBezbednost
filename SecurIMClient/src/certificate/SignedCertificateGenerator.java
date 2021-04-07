package certificate;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

public class SignedCertificateGenerator {

	private static String KEY_STORE_FILE = "./data/ca.jks";

	public SignedCertificateGenerator(String commonName, String surname,
			
		String givenName, String orgName, String orgUnit, String country,
		String email, KeyStoreReader keyStoreReader) {

		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		builder.addRDN(BCStyle.CN, commonName);
		builder.addRDN(BCStyle.SURNAME, surname);
		builder.addRDN(BCStyle.GIVENNAME, givenName);
		builder.addRDN(BCStyle.O, orgName);
		builder.addRDN(BCStyle.OU, orgUnit);
		builder.addRDN(BCStyle.C, country);
		builder.addRDN(BCStyle.E, email);
		builder.addRDN(BCStyle.UID, "123445");

		CertificateGenerator cg = new CertificateGenerator();

		

		
		Date startDate = null;
		Date endDate = null;
		final java.util.Calendar cal = GregorianCalendar.getInstance();
		startDate = cal.getTime();
		cal.setTime(startDate);
		cal.add(GregorianCalendar.YEAR, 2);
		endDate = cal.getTime();
		String sn = "1";

		IssuerData issuerData = null;
		try {
			issuerData = keyStoreReader.readKeyStore(KEY_STORE_FILE, "ca", "ca10".toCharArray(), "ca10".toCharArray());
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		
		KeyPair keyPair = cg.generateKeyPair();
		
		SubjectData subjectData = new SubjectData(keyPair.getPublic(),
				builder.build(), sn, startDate, endDate);
		
		
		
		
		X509Certificate cert = cg.generateCertificate(issuerData, subjectData);

		KeyStoreWriter keyStoreWriter = new KeyStoreWriter();
		
		keyStoreWriter.loadKeyStore(null, commonName.toCharArray());
		keyStoreWriter.write(commonName, keyPair.getPrivate(), commonName.toCharArray(), cert);
		keyStoreWriter.saveKeyStore("./data/" + commonName + ".jks",commonName.toCharArray());
		
		
		System.out.println(keyPair.getPrivate().toString()+"--------***************************************************************");
		System.out.println("ISSUER: " + cert.getIssuerX500Principal().getName());
		System.out.println("SUBJECT: " + cert.getSubjectX500Principal().getName());
		System.out.println("Sertifikat:");
		System.out.println("-------------------------------------------------------");
		System.out.println(cert);
		System.out.println("-------------------------------------------------------");
		try {
			cert.verify(keyStoreReader.readPublicKey());
			System.out.println("Validacija uspešna.");
		} catch (InvalidKeyException | CertificateException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			System.out.println("Validacija neuspešna");
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {

		KeyStoreReader ksr = new KeyStoreReader();
		SignedCertificateGenerator cg1 = new SignedCertificateGenerator("usera", "markovic", "mare", "ftn", "uns", "srbija", "mika@mika.com", ksr);
		SignedCertificateGenerator cg2 = new SignedCertificateGenerator("userb", "peric", "pera", "ftn", "uns", "srbija", "pera@pera.com", ksr);
	}
}
