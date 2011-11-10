/**
 * 
 */
package junit.de.bund.bsi.animamea.pace;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.animamea.asn1.bc.SecurityInfos;
import de.bund.bsi.animamea.pace.PaceParameter;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
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
	 * Test method for {@link de.bund.bsi.animamea.pace.PaceParameter#PaceParameter(de.bund.bsi.animamea.asn1.bc.PaceInfo, byte[], int)}.
	 */
	@Test
	public void testPaceParameterPaceInfoByteArrayInt() {
		PaceParameter pp1 = new PaceParameter(si.getPaceInfoList().get(0), new byte[]{0,0,0,0,1}, 1);
	}

	/**
	 * Test method for {@link de.bund.bsi.animamea.pace.PaceParameter#PaceParameter(de.bund.bsi.animamea.asn1.bc.PaceInfo, de.bund.bsi.animamea.asn1.bc.PaceDomainParameterInfo, byte[], int)}.
	 * @throws Exception 
	 */
	@Test
	public void testPaceParameterPaceInfoPaceDomainParameterInfoByteArrayInt() throws Exception {
		PaceParameter pp2 = new PaceParameter(si.getPaceInfoList().get(0), si.getPaceDomainParameterInfoList().get(0) , new byte[]{0,0,0,0,1}, 1);
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
