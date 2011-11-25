/**
 * 
 */
package junit.de.tsenger.animamea.asn1.bc;

import static de.tsenger.animamea.asn1.bc.BSIObjectIdentifiers.id_AT;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.asn1.bc.CertificateHolderAuthorizationTemplate;
import de.tsenger.animamea.asn1.bc.DiscretionaryData;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CertificateHolderAuthorizationTemplateTest {
	
	CertificateHolderAuthorizationTemplate chat = null;
	DiscretionaryData dd = null;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		dd = new DiscretionaryData(new byte[]{0,0,0,1,16});
		chat = new CertificateHolderAuthorizationTemplate(id_AT, dd);
	}

	/**
	 * Test method for {@link org.bouncycastle.asn1.ASN1Encodable#getEncoded(java.lang.String)}.
	 * @throws IOException 
	 */
	@Test
	public void testGetEncodedString() throws IOException {
		System.out.println(HexString.bufferToHex(chat.getEncoded()));
		fail("Not yet implemented");
	}

}
