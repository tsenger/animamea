/**
 *  Copyright 2011, Tobias Senger
 *  
 *  This file is part of animamea.
 *
 *  Animamea is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Animamea is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License   
 *  along with animamea.  If not, see <http://www.gnu.org/licenses/>.
 */
package junit.de.tsenger.animamea.asn1;

import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.asn1.CVCertificate;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CVCertificateTest {
	
	byte[] cvBytes = null;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() {
		cvBytes = readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/certs/CVCA_DETESTeID00002_DETESTeID00001.cvcert");
//		cvBytes = readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/certs/DV_DEDVTIDBSIDE003_DETESTeID00002.cvcert");
//		cvBytes = readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/certs/AT_DEATTIDBSIDE003_DEDVTIDBSIDE003.cvcert");
	}

	/**
	 * Test method for {@link de.tsenger.animamea.asn1.CVCertificate#CVCertificate(byte[])}.
	 */
	@Test
	public void testCVCertificate() {
		try {
			new CVCertificate(cvBytes);
		} catch (IllegalArgumentException e) {
			fail(e.getMessage());
		} catch (IOException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testSignature() {
		try {
			CVCertificate cert = new CVCertificate(cvBytes);
			System.out.println("Signature:\n"+HexString.bufferToHex(cert.getSignature().getDEREncoded()));
		} catch (IllegalArgumentException e) {
			fail(e.getMessage());
		} catch (IOException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testBody() {
		try {
			CVCertificate cert = new CVCertificate(cvBytes);
			cert.getBody();
			System.out.println("Body:\n"+HexString.bufferToHex(cert.getBody().getDEREncoded()));
			System.out.println(cert.getBody().toString());
		} catch (IllegalArgumentException e) {
			fail(e.getMessage());
		} catch (IOException e) {
			fail(e.getMessage());
		}
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
