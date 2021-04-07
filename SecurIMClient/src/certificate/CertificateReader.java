package certificate;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class CertificateReader {

	public static final String BASE64_ENC_CERT_FILE = "./data/usera_Lazar.cer";
	public static final String BIN_ENC_CERT_FILE = "./data/userb_Lazar.cer";
	
	public void testIt(String CERTIFICATE) {
		System.out.println("Cita sertifikat iz Base64 formata");
		readFromBase64EncFile(CERTIFICATE);
	}
	
	
	private void readFromBase64EncFile(String CERTIFICATE) {
		try {
			FileInputStream fis = new FileInputStream(CERTIFICATE);
			 BufferedInputStream bis = new BufferedInputStream(fis);

			 CertificateFactory cf = CertificateFactory.getInstance("X.509");
			 while (bis.available() > 0) {
			    Certificate cert = cf.generateCertificate(bis);
			    System.out.println(cert.toString());
			 }
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
