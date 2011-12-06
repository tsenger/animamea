/**
 * 
 */
package junit.de.tsenger.animamea.pace;

import static org.junit.Assert.assertTrue;

import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.pace.Pace;
import de.tsenger.animamea.pace.PaceECDH;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class PaceECDHTest {

	byte[] nonce_s = Hex.decode("7D98C00FC6C9E9543BBF94A87073A123");
	byte[] X1 = Hex.decode("043DD29BBE5907FD21A152ADA4895FAA"
			+ "E7ACC55F5E50EFBFDE5AB0C6EB54F198"
			+ "D615913635F0FDF5BEB383E00355F82D"
			+ "3C41ED0DF2E28363433DFB73856A15DC" + "9F");
	byte[] Y1 = Hex.decode("049CFCF7582AC986D0DD52FA53123414"
			+ "C3E1B96B4D00ABA8E574679B70EFB5BC"
			+ "3B45D2F13729CC2AE178E7E241B44321"
			+ "3533B77DBB44649A815DDC4A2384BA42" + "2A");
	byte[] X2 = Hex.decode("04518BC4E532AD2A9BD6527804D5D665"
			+ "ABD51041037A0CC8AA922804EB501C22"
			+ "2B3427388599AFAAE9FBACE2DF93E13C"
			+ "3C4979CD12F0AE3E3C01260283915545" + "82");
	byte[] Y2 = Hex.decode("04282CF38073036AFAC216AF135BD994"
			+ "DA0C357F10BD4C34AFEA1042B2EB0FD6"
			+ "804DF3658B835AC2E7133F1369118454"
			+ "2BB50B109963A4662ABDC08B9763AF4B" + "5B");
	byte[] K = Hex.decode("6E7D077CCD367C2EAA683F1E8EC53430"
			+ "2E2D00B6ADAF8A87A6EDA78740F17606");

	Pace pace = null;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		pace = new PaceECDH(TeleTrusTNamedCurves.getByName("brainpoolp256r1"));
	}

	/**
	 * Test method for {@link de.tsenger.animamea.pace.PaceECDH#getX1(byte[])}.
	 */
	@Test
	public void testGetX1() {
		byte[] cX1 = pace.getX1(nonce_s);
		System.out.println("X1:\n" + HexString.bufferToHex(cX1));
		assertTrue(Arrays.areEqual(cX1, X1));
	}

	/**
	 * Test method for {@link de.tsenger.animamea.pace.PaceECDH#getX2(byte[])}.
	 */
	@Test
	public void testGetX2() {
		pace.getX1(nonce_s);
		byte[] cX2 = pace.getX2(Y1);
		System.out.println("X2:\n" + HexString.bufferToHex(cX2));
		assertTrue(Arrays.areEqual(cX2, X2));
	}

	/**
	 * Test method for
	 * {@link de.tsenger.animamea.pace.PaceECDH#getSharedSecret_K(byte[])}.
	 */
	@Test
	public void testGetSharedSecret_K() {
		pace.getX1(nonce_s);
		pace.getX2(Y1);
		byte[] cK = pace.getSharedSecret_K(Y2);
		System.out.println("K:\n" + HexString.bufferToHex(cK));
		assertTrue(Arrays.areEqual(cK, K));
	}

}
