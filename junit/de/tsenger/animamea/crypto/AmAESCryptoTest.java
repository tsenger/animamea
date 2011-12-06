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
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class AmAESCryptoTest {

	private AmAESCrypto aes_enc = null;
	private AmAESCrypto aes_mac = null;
	private final byte[] plainBytes = Hex
			.decode("00112233445566778899aabbccddeeff");
	private final byte[] plainBytes2 = Hex
			.decode("830d44455445535444564445303139");
	private final byte[] encryptedBytes = Hex
			.decode("dda97ca4864cdfe06eaf70a0ec0d7191b55321312995c4489612370cc7fbef79");;
	private final byte[] encryptedBytes2 = Hex
			.decode("a7bb8f230fff9221162ad673b9f319a8");
	private final byte[] key = Hex.decode("68406b4162100563d9c901a6154d2901");
	private final byte[] key2 = Hex.decode("73ff268784f72af833fdc9464049afc9");
	private final byte[] m = Hex
			.decode("0c2281b6800000000000000000000000871101a7bb8f230fff9221162ad673b9f319a8");
	private final byte[] cc1 = Hex.decode("d8713e9b7a600b49");

	byte[] keyBytes128 = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
	byte[] input16 = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
	byte[] output_k128_m16 = Hex.decode("070a16b46b4d4144f79bdd9dd04a287c");

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		aes_enc = new AmAESCrypto();
		aes_mac = new AmAESCrypto();

	}

	/**
	 * Test method for
	 * {@link de.tsenger.animamea.crypto.AmAESCrypto#encrypt(java.io.InputStream, java.io.OutputStream)}
	 * .
	 * 
	 * @throws IOException
	 * @throws InvalidCipherTextException
	 * @throws IllegalStateException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws ShortBufferException
	 * @throws DataLengthException
	 */
	@Test
	public void testEncrypt() throws DataLengthException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException,
			IllegalStateException, InvalidCipherTextException, IOException {

		aes_enc.init(key, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, (byte) 5 });
		byte[] c = aes_enc.encrypt(plainBytes2);
		assertTrue(Arrays.areEqual(c, encryptedBytes2));
	}

	/**
	 * Test method for
	 * {@link de.tsenger.animamea.crypto.AmAESCrypto#decrypt(java.io.InputStream, java.io.OutputStream)}
	 * .
	 * 
	 * @throws IOException
	 * @throws InvalidCipherTextException
	 * @throws IllegalStateException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws ShortBufferException
	 * @throws DataLengthException
	 */
	@Test
	public void testDecrypt() throws DataLengthException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException,
			IllegalStateException, InvalidCipherTextException, IOException {
		aes_enc.init(key, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, (byte) 5 });
		byte[] p = aes_enc.decrypt(encryptedBytes2);
		assertTrue(Arrays.areEqual(p, plainBytes2));

	}

	@Test
	public void testGetMAC() {
		aes_mac.init(key2, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, (byte) 5 });
		byte[] cc = aes_mac.getMAC(m);
		System.out.println(HexString.bufferToHex(cc));
		assertTrue(Arrays.areEqual(cc, cc1));
	}

}
