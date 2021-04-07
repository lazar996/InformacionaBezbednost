package certificate;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class CertificateGenerator {
		static {
			Security.addProvider(new BouncyCastleProvider());
		}
		
		public X509Certificate generateCertificate(IssuerData issuerData, SubjectData subjectData) {
			 try {
				 		 
				 JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
				 builder = builder.setProvider("BC");
				 			 
				 ContentSigner contentSigner = builder.build(issuerData.getPrivateKey());
				 			 
				 X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuerData.getX500name(),
						 															new BigInteger(subjectData.getSerialNumber()),
						 															subjectData.getStartDate(),
						 															subjectData.getEndDate(),
						 															subjectData.getX500name(),
						 															subjectData.getPublicKey());

				 X509CertificateHolder certHolder = certGen.build(contentSigner);				
				 JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
				 certConverter = certConverter.setProvider("BC");
				 
				 return certConverter.getCertificate(certHolder);
				 
			 } catch (CertificateEncodingException e) {
				e.printStackTrace();
				return null;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
				return null;
			} catch (IllegalStateException e) {
				e.printStackTrace();
				return null;
			} catch (OperatorCreationException e) {
				e.printStackTrace();
				return null;
			} catch (CertificateException e) {
				e.printStackTrace();
				return null;
			}
		}
		
		public KeyPair generateKeyPair() {
			try {
				KeyPairGenerator   keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(1024);
				
				KeyPair pair = keyGen.generateKeyPair();
				
				return pair;
				
	        } catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			}
		}
		

}
