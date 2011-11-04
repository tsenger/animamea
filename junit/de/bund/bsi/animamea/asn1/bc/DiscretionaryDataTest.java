/**
 * 
 */
package junit.de.bund.bsi.animamea.asn1.bc;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.animamea.asn1.bc.DiscretionaryData;
import de.bund.bsi.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class DiscretionaryDataTest {
	
	DiscretionaryData dd = null;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		byte[] auth = new byte[] {0,0,0,1,16};
		byte auth2 = (byte) 0xFF;
		dd = new DiscretionaryData(auth);
	}

	/**
	 * Test method for {@link de.bund.bsi.animamea.asn1.bc.DiscretionaryData#getEncoded()}.
	 * @throws IOException 
	 */
	@Test
	public void testGetEncoded() throws IOException {
		System.out.println(HexString.bufferToHex(dd.getEncoded()));
		
		assertTrue(dd.getEncoded().equals(HexString.hexToBuffer("53050000000110")));
	}

}
