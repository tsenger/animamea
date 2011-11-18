/**
 * 
 */
package junit.de.bund.bsi.animamea.tools;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.animamea.tools.Converter;
import de.bund.bsi.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class ConverterTest {

	byte[] array = Hex.decode("FF11223344556677");
	long ssc = 0;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * Test method for {@link de.bund.bsi.animamea.tools.Converter#longToByteArray(long)}.
	 */
	@Test
	public void testLongToByteArray() {
		ssc = Converter.ByteArrayToLong(array);
		System.out.println(ssc);		
		System.out.println(HexString.bufferToHex(Converter.longToByteArray(ssc)));
		
	}

}
