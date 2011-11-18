/**
 * 
 */
package junit.de.bund.bsi.animamea.iso7816;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.animamea.iso7816.DO87;
import de.bund.bsi.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class DO87Test {
	
	DO87 do87 = null;
	byte[] data = Hex.decode("0011223380000000");
	byte[] asn1coded = Hex.decode("8709010011223380000000");

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		do87 = new DO87(data);
	}

	/**
	 * Test method for {@link de.bund.bsi.animamea.iso7816.DO87#DO87(byte[])}.
	 * @throws IOException 
	 */
	@Test
	public void testDO87ByteArray() throws IOException {
		System.out.println(HexString.bufferToHex(do87.getEncoded()));
		assertTrue(Arrays.areEqual(asn1coded, do87.getEncoded()));
	}
	
	/**
	 * Test method for {@link de.bund.bsi.animamea.iso7816.DO87#DO87(byte[])}.
	 */
	@Test
	public void testDO87Decode() {
		do87 = new DO87();
		do87.decode(asn1coded);
		assertTrue(Arrays.areEqual(data, do87.getData()));
	}

}
