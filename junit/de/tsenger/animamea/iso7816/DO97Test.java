/**
 * 
 */
package junit.de.tsenger.animamea.iso7816;

import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.iso7816.DO97;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class DO97Test {
	
	byte le = (byte)0x10;
	byte[] le2 = new byte[]{(byte)0x81, (byte)0xF2};
	DO97 do97 = null;
	byte[] asn1coded = new byte[]{(byte)0x97, (byte)0x01, (byte)0x10};
	byte[] asn1coded2 = new byte[]{(byte)0x97, (byte)0x02, (byte)0x81, (byte)0xf2};

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		do97 = new DO97(le2);
	}


	/**
	 * Test method for {@link de.tsenger.animamea.iso7816.DO97#DO97(byte)}.
	 */
	@Test
	public void testDO97Byte() {
		System.out.println(HexString.bufferToHex(do97.getEncoded()));
	}

	/**
	 * Test method for {@link de.tsenger.animamea.iso7816.DO97#decode(byte[])}.
	 */
	@Test
	public void testDecode() {
		do97 = new DO97();
		do97.fromByteArray(asn1coded2);
		System.out.println(HexString.bufferToHex(do97.getData()));
	}

}
