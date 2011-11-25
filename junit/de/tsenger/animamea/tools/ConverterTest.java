/**
 * 
 */
package junit.de.tsenger.animamea.tools;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.tools.Converter;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
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
	 * Test method for {@link de.tsenger.animamea.tools.Converter#longToByteArray(long)}.
	 */
	@Test
	public void testLongToByteArray() {
		ssc = Converter.ByteArrayToLong(array);
		System.out.println(ssc);		
		System.out.println(HexString.bufferToHex(Converter.longToByteArray(ssc)));
		
	}

}
