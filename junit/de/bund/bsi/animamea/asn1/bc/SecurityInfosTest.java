package junit.de.bund.bsi.animamea.asn1.bc;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.animamea.asn1.bc.SecurityInfos;

/**
*
* @author Tobias Senger (tobias.senger@bsi.bund.de)
*/
public class SecurityInfosTest {
	
	SecurityInfos si = null;

	@Before
	public void setUp() throws Exception {
		si = new SecurityInfos();
	}


	@Test
	public void testDecode() {
		try {
//			si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/2011-07-13_X00301950_EF.CardAccess.bin"));
//			si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/EF_CardAccess_001.bin"));
			si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/EF_CardAccess_echt_npa.bin"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println(si.getChipAuthenticationDomainParameterInfoList().get(0).getProtocolOID());
		System.out.println(si.getChipAuthenticationDomainParameterInfoList().get(0).getDomainParameter().getAlgorithm());
		System.out.println(si);
		assertTrue(si.getChipAuthenticationDomainParameterInfoList().size()!=0);
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
