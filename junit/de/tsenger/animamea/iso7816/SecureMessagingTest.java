/**
 * 
 */
package junit.de.tsenger.animamea.iso7816;

import static org.junit.Assert.assertTrue;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.crypto.AmAESCrypto;
import de.tsenger.animamea.crypto.AmDESCrypto;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class SecureMessagingTest {
	
	SecureMessaging sm = null;
	ResponseAPDU rapdu = null;
	CommandAPDU capdu = null;
	
	byte[] initialSSC1 = Hex.decode("887022120C06C226");
	byte[] initialSSC2 = Hex.decode("887022120C06C229");
	
	byte[] kenc = Hex.decode("979ec13b1cbfe9dcd01ab0fed307eae5");
	byte[] kmac = Hex.decode("f1cb1f1fb5adf208806b89dc579dc1f8");
	
	byte[] kenc_AES = Hex.decode("68406b4162100563d9c901a6154d2901");
	byte[] kmac_AES = Hex.decode("73ff268784f72af833fdc9464049afc9");
	
	byte[] crypt_resp1_AES = Hex.decode("990290008e08c8488f79fef386c79000"); 
	byte[] plain_resp1_AES = Hex.decode("9000");
	
	byte[] plain_cmd1_AES = Hex.decode("002281b60f830d44455445535444564445303139");
	byte[] crypt_cmd1_AES = Hex.decode("0c2281b61d871101a7bb8f230fff9221162ad673b9f319a88e08d8713e9b7a600b4900");
	
	byte[] crypt_resp1 = Hex.decode("8709019ff0ec34f9922651990290008e08ad55cc17140b2ded9000"); 
	byte[] plain_resp1 = Hex.decode("60145f019000");
	
	byte[] plain_cmd1 = Hex.decode("00a4020c02011e");
	byte[] crypt_cmd1 = Hex.decode("0ca4020c158709016375432908c044f68e08bf8b92d635ff24f800");
	
	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() {
		rapdu = new ResponseAPDU(crypt_resp1);
		capdu = new CommandAPDU(plain_cmd1);
		
	}

	/**
	 * Test method for {@link de.tsenger.animamea.iso7816.SecureMessaging#wrap(javax.smartcardio.CommandAPDU)}.
	 * @throws Exception 
	 */
	@Test
	public void testWrap() throws Exception {
		sm = new SecureMessaging(new AmDESCrypto(), kenc, kmac, initialSSC1);
		CommandAPDU pc = sm.wrap(capdu);
		System.out.println("wrap():\n"+HexString.bufferToHex(pc.getBytes()));
		assertTrue(Arrays.areEqual(crypt_cmd1, pc.getBytes()));
	}

	/**
	 * Test method for {@link de.tsenger.animamea.iso7816.SecureMessaging#unwrap(javax.smartcardio.ResponseAPDU)}.
	 * @throws Exception 
	 */
	@Test
	public void testUnwrap() throws Exception {
		sm = new SecureMessaging(new AmDESCrypto(), kenc, kmac, initialSSC2);
		ResponseAPDU ur = sm.unwrap(rapdu);
		System.out.println("unwrap():\n"+HexString.bufferToHex(ur.getBytes()));
		assertTrue(Arrays.areEqual(plain_resp1, ur.getBytes()));
	}
	

	/**
	 * Test method for {@link de.tsenger.animamea.iso7816.SecureMessaging#wrap(javax.smartcardio.CommandAPDU)}.
	 * @throws Exception 
	 */
	@Test
	public void testWrapAES() throws Exception {
		sm = new SecureMessaging(new AmAESCrypto(), kenc_AES, kmac_AES, new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(byte)4});
		CommandAPDU pc = sm.wrap(new CommandAPDU(plain_cmd1_AES));
		System.out.println("wrap():\n"+HexString.bufferToHex(pc.getBytes()));
		assertTrue(Arrays.areEqual(crypt_cmd1_AES, pc.getBytes()));
	}

	/**
	 * Test method for {@link de.tsenger.animamea.iso7816.SecureMessaging#unwrap(javax.smartcardio.ResponseAPDU)}.
	 * @throws Exception 
	 */
	@Test
	public void testUnwrapAES() throws Exception {
		sm = new SecureMessaging(new AmAESCrypto(), kenc_AES, kmac_AES, new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(byte)5});
		ResponseAPDU ur = sm.unwrap(new ResponseAPDU(crypt_resp1_AES));
		System.out.println("unwrap():\n"+HexString.bufferToHex(ur.getBytes()));
		assertTrue(Arrays.areEqual(plain_resp1_AES, ur.getBytes()));
	}

}
