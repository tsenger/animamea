/**
 * 
 */
package junit.de.bund.bsi.animamea.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.animamea.crypto.AmAESCrypto;
import de.bund.bsi.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class AmAESCryptoTest {
	
	private AmAESCrypto aes = null;
	private final byte[] plainBytes = Hex.decode("00112233445566778899aabbccddeeff");
	private final byte[] encryptedBytes= Hex.decode("dda97ca4864cdfe06eaf70a0ec0d7191b55321312995c4489612370cc7fbef79");;
	private final byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617");
	private final byte[] iv = Hex.decode("00000000000000000000000000000000");

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		aes = new AmAESCrypto();
		aes.initCiphers(key, iv);
		
	}

	

	/**
	 * Test method for {@link de.bund.bsi.animamea.crypto.AmAESCrypto#encrypt(java.io.InputStream, java.io.OutputStream)}.
	 */
	@Test
	public void testEncrypt() {
		
		
		byte[] enc = null;
		try {
			enc = aes.encrypt(plainBytes);
		} catch (DataLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("Encrypted:\n"+HexString.bufferToHex(enc));
	}
	
	/**
	 * Test method for {@link de.bund.bsi.animamea.crypto.AmAESCrypto#decrypt(java.io.InputStream, java.io.OutputStream)}.
	 */
	@Test
	public void testDecrypt() {
		
		ByteArrayInputStream bis = new ByteArrayInputStream(encryptedBytes);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		
		try {
			aes.decrypt(bis, bos);
		} catch (DataLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("Decrypted:\n"+HexString.bufferToHex(bos.toByteArray()));
		
	}


}
