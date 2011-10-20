package junit.de.bund.bsi.jasmin.asn1.bc;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.jasmin.asn1.bc.PaceInfo;

/**
*
* @author Tobias Senger (tobias.senger@bsi.bund.de)
*/
public class PaceInfoTest {
	
	PaceInfo pi1 = null;

	@Before
	public void setUp() throws Exception {
		
	}

	@Test
	public void testPaceInfoDERSequence() {
		fail("Not yet implemented");
	}

	@Test
	public void testPaceInfoStringIntInt() {
		pi1= null;
		try {
			pi1 = new PaceInfo("0.4.0.127.2.2.4.2",1,1);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		assertTrue(pi1.getProtocolString().equals("0.4.0.127.2.2.4.2"));
	}

	@Test
	public void testGetProtocolString() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetProtocolBytes() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetVersion() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetParameterId() {
		fail("Not yet implemented");
	}

}
