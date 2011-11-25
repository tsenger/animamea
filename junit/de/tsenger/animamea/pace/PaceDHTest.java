/**
 * 
 */
package junit.de.tsenger.animamea.pace;

import static de.tsenger.animamea.pace.DHStandardizedDomainParameters.modp1024_160;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.pace.Pace;
import de.tsenger.animamea.pace.PaceDH;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class PaceDHTest {
	
	Pace pacedh = null;
	byte[] s = Hex.decode("FA5B7E3E49753A0DB9178B7B9BD898C8");
	byte[] X1 = Hex.decode("23FB3749EA030D2A25B278D2A562047A" +
			"DE3F01B74F17A15402CB7352CA7D2B3E" +
			"B71C343DB13D1DEBCE9A3666DBCFC920" +
			"B49174A602CB47965CAA73DC702489A4" +
			"4D41DB914DE9613DC5E98C94160551C0" +
			"DF86274B9359BC0490D01B03AD54022D" +
			"CB4F57FAD6322497D7A1E28D46710F46" +
			"1AFE710FBBBC5F8BA166F4311975EC6C");
	byte[] Y1 = Hex.decode("78879F57225AA8080D52ED0FC890A4B2" +
			"5336F699AA89A2D3A189654AF70729E6" +
			"23EA5738B26381E4DA19E004706FACE7" +
			"B235C2DBF2F38748312F3C98C2DD4882" +
			"A41947B324AA1259AC22579DB93F7085" +
			"655AF30889DBB845D9E6783FE42C9F24" +
			"49400306254C8AE8EE9DD812A804C0B6" +
			"6E8CAFC14F84D8258950A91B44126EE6");
	byte[] X2 = Hex.decode("907D89E2D425A178AA81AF4A7774EC" +
			"8E388C115CAE67031E85EECE520BD911" +
			"551B9AE4D04369F29A02626C86FBC674" +
			"7CC7BC352645B6161A2A42D44EDA80A0" +
			"8FA8D61B76D3A154AD8A5A51786B0BC0" +
			"7147057871A922212C5F67F431731722" +
			"36B7747D1671E6D692A3C7D40A0C3C5C" +
			"E397545D015C175EB5130551EDBC2EE5" +
			"D4");
	byte[] Y2 = Hex.decode("075693D9AE941877573E634B6E644F8E" +
			"60AF17A0076B8B123D9201074D36152B" +
			"D8B3A213F53820C42ADC79AB5D0AEEC3" +
			"AEFB91394DA476BD97B9B14D0A65C1FC" +
			"71A0E019CB08AF55E1F729005FBA7E3F" +
			"A5DC41899238A250767A6D46DB974064" +
			"386CD456743585F8E5D90CC8B4004B1F" +
			"6D866C79CE0584E49687FF61BC29AEA1");
	byte[] K = Hex.decode("6BABC7B3A72BCD7EA385E4C62DB2625B" +
			"D8613B24149E146A629311C4CA6698E3" +
			"8B834B6A9E9CD7184BA8834AFF5043D4" +
			"36950C4C1E7832367C10CB8C314D40E5" +
			"990B0DF7013E64B4549E2270923D06F0" +
			"8CFF6BD3E977DDE6ABE4C31D55C0FA2E" +
			"465E553E77BDF75E3193D3834FC26E8E" +
			"B1EE2FA1E4FC97C18C3F6CFFFE2607FD");

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		pacedh = new PaceDH(modp1024_160());
	}

	/**
	 * Test method for {@link de.tsenger.animamea.pace.PaceDH#getX1(byte[])}.
	 */
	@Test
	public void testGetX1() {
		byte[] cX1 = pacedh.getX1(s);
		System.out.println("X1:\n"+HexString.bufferToHex(cX1));
		assertTrue(Arrays.areEqual(X1, cX1));
	}

	/**
	 * Test method for {@link de.tsenger.animamea.pace.PaceDH#getX2(byte[])}.
	 */
	@Test
	public void testGetX2() {
		pacedh.getX1(s);
		byte[] cX2 = pacedh.getX2(Y1);
		System.out.println("X2:\n"+HexString.bufferToHex(cX2));
		assertTrue(Arrays.areEqual(X2, cX2));
	}

	/**
	 * Test method for {@link de.tsenger.animamea.pace.PaceDH#getSharedSecret_K(byte[])}.
	 */
	@Test
	public void testGetSharedSecret_K() {
		pacedh.getX1(s);
		pacedh.getX2(Y1);
		byte[] cK = pacedh.getSharedSecret_K(Y2);
		System.out.println("K:\n"+HexString.bufferToHex(K));
		assertTrue(Arrays.areEqual(K, cK));
	}

}
