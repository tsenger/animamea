/**
 * 
 */
package junit.de.tsenger.animamea.crypto;

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

import de.tsenger.animamea.crypto.AmAESCrypto;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class AmAESCryptoTest {
	
	private AmAESCrypto aes_enc = null;
	private AmAESCrypto aes_mac = null;
	private final byte[] plainBytes = Hex.decode("00112233445566778899aabbccddeeff");
	private final byte[] encryptedBytes= Hex.decode("dda97ca4864cdfe06eaf70a0ec0d7191b55321312995c4489612370cc7fbef79");;
	private final byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617");
	private final byte[] m = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
	private final byte[] cc1 = Hex.decode("002ffdcd32f620b6");

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		aes_enc = new AmAESCrypto();
		aes_mac = new AmAESCrypto();
		
		aes_enc.init(key, 0L);
		aes_mac.init(key, 0L);
	}

	

	/**
	 * Test method for {@link de.tsenger.animamea.crypto.AmAESCrypto#encrypt(java.io.InputStream, java.io.OutputStream)}.
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
		byte[] c = aes_enc.encrypt(plainBytes);
		assertTrue(Arrays.areEqual(c, encryptedBytes));
	}
	
	/**
	 * Test method for {@link de.tsenger.animamea.crypto.AmAESCrypto#decrypt(java.io.InputStream, java.io.OutputStream)}.
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
		byte[] p = aes_enc.decrypt(encryptedBytes);
		assertTrue(Arrays.areEqual(p, plainBytes));
		
	}
	
	@Test
	public void testGetMAC() {
		byte[] cc = aes_mac.getMAC(m);
		assertTrue(Arrays.areEqual(cc, cc1));
	}


}
