/**
 * 
 */
package junit.de.bund.bsi.animamea.crypto;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.animamea.crypto.AmCryptoProvider;
import de.bund.bsi.animamea.crypto.AmDESCrypto;
import de.bund.bsi.animamea.tools.Converter;
import de.bund.bsi.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class AmDESCryptoTest {
	
	AmCryptoProvider cp_enc = null;
	AmCryptoProvider cp_mac = null;
	byte[] kenc = Hex.decode("979ec13b1cbfe9dcd01ab0fed307eae5");
	byte[] kmac = Hex.decode("f1cb1f1fb5adf208806b89dc579dc1f8");
	
	byte[] plain1 = Hex.decode("011e");
	byte[] cipher1 = Hex.decode("6375432908c044f6");
	
	byte[] m = Hex.decode("0ca4020c800000008709016375432908c044f6");
	byte[] cc1 = Hex.decode("bf8b92d635ff24f8");

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		cp_enc = new AmDESCrypto();
		cp_mac = new AmDESCrypto();
		
		cp_enc.init(kenc, 0L);
		cp_mac.init(kmac, Converter.ByteArrayToLong(Hex.decode("887022120C06C227")));
		
	}


	/**
	 * Test method for {@link de.bund.bsi.animamea.crypto.AmDESCrypto#getMAC(byte[])}.
	 */
	@Test
	public void testGetMAC() {
		byte[] cc = cp_mac.getMAC(m);
		assertTrue(Arrays.areEqual(cc, cc1));
	}

	/**
	 * Test method for {@link de.bund.bsi.animamea.crypto.AmCryptoProvider#encrypt(byte[])}.
	 * @throws IOException 
	 * @throws InvalidCipherTextException 
	 * @throws IllegalStateException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws ShortBufferException 
	 * @throws DataLengthException 
	 */
	@Test
	public void testEncrypt() throws DataLengthException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidCipherTextException, IOException {
		byte[] c = cp_enc.encrypt(plain1);
		assertTrue(HexString.bufferToHex(c), Arrays.areEqual(c, cipher1));
	}

	/**
	 * Test method for {@link de.bund.bsi.animamea.crypto.AmCryptoProvider#decrypt(byte[])}.
	 * @throws IOException 
	 * @throws InvalidCipherTextException 
	 * @throws IllegalStateException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws ShortBufferException 
	 * @throws DataLengthException 
	 */
	@Test
	public void testDecrypt() throws DataLengthException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidCipherTextException, IOException {
		byte[] p = cp_enc.decrypt(cipher1);
		assertTrue(HexString.bufferToHex(p), Arrays.areEqual(p, plain1));
	}

}
