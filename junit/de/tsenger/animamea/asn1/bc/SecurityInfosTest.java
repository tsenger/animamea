package junit.de.tsenger.animamea.asn1.bc;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.asn1.SecurityInfos;

/**
*
* @author Tobias Senger (tobias@t-senger.de)
*/
public class SecurityInfosTest {
	
	SecurityInfos si = null;

	@Before
	public void setUp() throws Exception {
		si = new SecurityInfos();
	}


	@Test
	public void testDecode() throws Exception {
		try {
//			si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/2011-07-13_X00301950_EF.CardAccess.bin"));
			si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/EF_CardAccess_001.bin"));
//			si.decode(readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/EF.CardAccess/EF_CardAccess_echt_npa.bin"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println(si.getChipAuthenticationDomainParameterInfoList().get(0).getProtocolOID());
		System.out.println(si.getChipAuthenticationDomainParameterInfoList().get(0).getDomainParameter().getParameters().getDERObject().toASN1Object());
		System.out.println(si);
		
		ASN1Sequence seq = (ASN1Sequence)si.getChipAuthenticationDomainParameterInfoList().get(0).getDomainParameter().getParameters().getDERObject().toASN1Object();
		X9ECParameters parameters = new X9ECParameters(seq);
		System.out.println(parameters.getN());
		
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
