/**
 * 
 */
package junit.de.tsenger.animamea.pace;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.asn1.EphemeralPublicKey;
import de.tsenger.animamea.asn1.SecurityInfos;
import de.tsenger.animamea.crypto.AmAESCrypto;
import de.tsenger.animamea.pace.PaceOperator;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class PaceOperatorTest {

	SecurityInfos si = null;
	PaceOperator pop1 = null;
	byte[] X2 = Hex.decode("04518BC4E532AD2A9BD6527804D5D665"
			+ "ABD51041037A0CC8AA922804EB501C22"
			+ "2B3427388599AFAAE9FBACE2DF93E13C"
			+ "3C4979CD12F0AE3E3C01260283915545" + "82");
	byte[] kmac = Hex.decode("73ff268784f72af833fdc9464049afc9");

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		si = new SecurityInfos();
		// si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/2011-07-13_X00301950_EF.CardAccess.bin"));
		// si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/EF_CardAccess_001.bin"));
		si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/EF_CardAccess_echt_npa.bin"));
		pop1 = new PaceOperator(null);
		pop1.setAuthTemplate(si.getPaceInfoList().get(0), "123456", 3, 0);
	}

	/**
	 * Test method for
	 * {@link de.tsenger.animamea.pace.PaceParameters#PaceParameter(de.tsenger.animamea.asn1.PaceInfo, byte[], int)}
	 * .
	 */
	@Test
	public void testPaceParameterPaceInfoByteArrayInt() {
		assertTrue(pop1 != null);
	}

//	@Test
//	public void testdecryptNonce() {
//		byte[] s = pop1.decryptNonce(Hex.decode("ce834cde69ffbb1d1eb21585cd709f18"));
//		assertTrue(Arrays.areEqual(s, Hex.decode("7d98c00fc6c9e9543bbf94a87073a123")));
//	}
//
//	@Test
//	public void testGetKenc() {
//		byte[] s = pop1.getKenc(Hex.decode("6E7D077CCD367C2EAA683F1E8EC534302E2D00B6ADAF8A87A6EDA78740F17606"));
//		assertTrue(Arrays.areEqual(s, Hex.decode("68406b4162100563d9c901a6154d2901")));
//	}
//
//	@Test
//	public void testGetKmac() {
//		byte[] s = pop1.getKmac(Hex.decode("6E7D077CCD367C2EAA683F1E8EC534302E2D00B6ADAF8A87A6EDA78740F17606"));
//		assertTrue(Arrays.areEqual(s, kmac));
//	}

	@Test
	public void testAuthToken() throws Exception {
		EphemeralPublicKey pkpicc = new EphemeralPublicKey(si.getPaceInfoList()
				.get(0).getProtocolOID(), X2);
		AmAESCrypto crypto = new AmAESCrypto();

		byte[] tpicc_strich = crypto.getMAC(kmac, pkpicc.getEncoded());
		System.out.println("t'picc: " + HexString.bufferToHex(tpicc_strich));
	}

	private byte[] readBinaryFile(String filename) {
		FileInputStream in = null;
		File efCardAccessFile = new File(filename);
		byte buffer[] = new byte[(int) efCardAccessFile.length()];

		try {
			in = new FileInputStream(efCardAccessFile);
			in.read(buffer, 0, buffer.length);
		} catch (FileNotFoundException ex) {
		} catch (IOException ex) {
		}

		return buffer;
	}

}
