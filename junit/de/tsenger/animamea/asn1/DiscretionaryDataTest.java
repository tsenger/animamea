/**
 * 
 */
package junit.de.tsenger.animamea.asn1;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.asn1.DiscretionaryData;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class DiscretionaryDataTest {

	DiscretionaryData dd = null;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		byte[] auth = new byte[] { 0, 0, 0, 1, 16 };
		byte auth2 = (byte) 0xFF;
		dd = new DiscretionaryData(auth);
	}

	/**
	 * Test method for
	 * {@link de.tsenger.animamea.asn1.DiscretionaryData#getEncoded()}.
	 * 
	 * @throws IOException
	 */
	@Test
	public void testGetEncoded() throws IOException {
		System.out.println(HexString.bufferToHex(dd.getEncoded()));

		assertTrue(Arrays.areEqual(dd.getEncoded(),
				HexString.hexToBuffer("53050000000110")));
	}

}
