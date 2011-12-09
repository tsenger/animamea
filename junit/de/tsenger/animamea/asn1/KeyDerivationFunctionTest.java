/**
 * 
 */
package junit.de.tsenger.animamea.asn1;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.KeyDerivationFunction;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class KeyDerivationFunctionTest {

	KeyDerivationFunction kdf1 = null;
	KeyDerivationFunction kdf2 = null;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * Test method for
	 * {@link de.tsenger.animamea.KeyDerivationFunction#getDESedeKey()}.
	 */
	@Test
	public void testGetDESedeKey() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link de.tsenger.animamea.KeyDerivationFunction#getAES128Key()}.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testGetAES128Key() throws Exception {
		byte[] pinBytes = "123456".getBytes();
		kdf1 = new KeyDerivationFunction(pinBytes, 3);
		assertTrue(Arrays.equals(kdf1.getAES128Key(),
				HexString.hexToBuffer("591468cda83d65219cccb8560233600f")));
	}

	/**
	 * Test method for
	 * {@link de.tsenger.animamea.KeyDerivationFunction#getAES192Key()}.
	 */
	@Test
	public void testGetAES192Key() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link de.tsenger.animamea.KeyDerivationFunction#getAES256Key()}.
	 */
	@Test
	public void testGetAES256Key() {
		fail("Not yet implemented");
	}

}
