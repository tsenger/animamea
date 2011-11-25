/**
 * 
 */
package junit.de.tsenger.animamea.pace;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.asn1.bc.SecurityInfos;
import de.tsenger.animamea.pace.PaceParameters;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class PaceParameterTest {
	
	SecurityInfos si = null;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		si = new SecurityInfos();
//		si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/2011-07-13_X00301950_EF.CardAccess.bin"));
		si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/EF_CardAccess_001.bin"));
//		si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/EF_CardAccess_echt_npa.bin"));
	}

	/**
	 * Test method for {@link de.tsenger.animamea.pace.PaceParameters#PaceParameter(de.tsenger.animamea.asn1.bc.PaceInfo, byte[], int)}.
	 */
	@Test
	public void testPaceParameterPaceInfoByteArrayInt() {
		PaceParameters pp1 = new PaceParameters(si.getPaceInfoList().get(0), new byte[]{0,0,0,0,1}, 1);
	}

	/**
	 * Test method for {@link de.tsenger.animamea.pace.PaceParameters#PaceParameter(de.tsenger.animamea.asn1.bc.PaceInfo, de.tsenger.animamea.asn1.bc.PaceDomainParameterInfo, byte[], int)}.
	 * @throws Exception 
	 */
	@Test
	public void testPaceParameterPaceInfoPaceDomainParameterInfoByteArrayInt() throws Exception {
		PaceParameters pp2 = new PaceParameters(si.getPaceInfoList().get(0), si.getPaceDomainParameterInfoList().get(0) , new byte[]{0,0,0,0,1}, 1);
	}
	
	private byte[] readBinaryFile(String filename) {
        FileInputStream in = null;
        File efCardAccessFile = new File(filename);
        byte buffer[] = new byte[(int)efCardAccessFile.length()];

        try {
            in = new FileInputStream(efCardAccessFile);
            in.read(buffer, 0, buffer.length);
        }
        catch (FileNotFoundException ex) {}
        catch (IOException ex) {}

        return buffer;
    }

}
