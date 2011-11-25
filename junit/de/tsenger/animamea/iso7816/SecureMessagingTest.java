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

import de.tsenger.animamea.crypto.AmDESCrypto;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.tools.Converter;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class SecureMessagingTest {
	
	SecureMessaging sm = null;
	ResponseAPDU rapdu = null;
	CommandAPDU capdu = null;
	
	long initialSSC1 = Converter.ByteArrayToLong(Hex.decode("887022120C06C226"));
	long initialSSC2 = Converter.ByteArrayToLong(Hex.decode("887022120C06C229"));
	
	byte[] kenc = Hex.decode("979ec13b1cbfe9dcd01ab0fed307eae5");
	byte[] kmac = Hex.decode("f1cb1f1fb5adf208806b89dc579dc1f8");
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

}
