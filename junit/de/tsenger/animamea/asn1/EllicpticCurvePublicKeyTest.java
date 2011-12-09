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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTags;
import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.asn1.EllicpticCurvePublicKey;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class EllicpticCurvePublicKeyTest {
	
	EllicpticCurvePublicKey pk = null;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		byte[] dataBytes = readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/certs/CVCA_DETESTeID00002_DETESTeID00001.cvcert");
		System.out.println(HexString.bufferToHex(dataBytes));
		ASN1StreamParser asn1Parser = new ASN1StreamParser(dataBytes);
		
		DERApplicationSpecific cvcert = (DERApplicationSpecific) asn1Parser.readObject();
		System.out.println(Integer.toHexString(cvcert.getApplicationTag()));
		DERSequence derCert= (DERSequence)cvcert.getObject(DERTags.SEQUENCE);
		
		DERApplicationSpecific certbody = (DERApplicationSpecific) derCert.getObjectAt(0);
		DERSequence derBody= (DERSequence)certbody.getObject(DERTags.SEQUENCE);
		System.out.println("CertBody:\n"+HexString.bufferToHex(derBody.getEncoded()));
		
		DERApplicationSpecific profileIdentifier = (DERApplicationSpecific) derBody.getObjectAt(0);
		DERInteger derPI= (DERInteger)profileIdentifier.getObject(DERTags.INTEGER);
		System.out.println("ProfileIdentifier:\n"+HexString.bufferToHex(derPI.getEncoded()));
		
		DERApplicationSpecific publikKey = (DERApplicationSpecific) derBody.getObjectAt(2);
		DERSequence derPK= (DERSequence)publikKey.getObject(DERTags.SEQUENCE);
		System.out.println("PublicKey:\n"+HexString.bufferToHex(derPK.getEncoded()));
		
		DEREncodable signature = derCert.getObjectAt(1);
		
		//System.out.println("Signatur:\n"+HexString.bufferToHex(signature.getDERObject().getEncoded()));
		
//		DERSequence derseq = (DERSequence) asn1seq.getDERObject();
		pk = new EllicpticCurvePublicKey(derPK);
	}

	/**
	 * Test method for {@link de.tsenger.animamea.asn1.PublicKey#PublicKey(org.bouncycastle.asn1.DERSequence)}.
	 */
	@Test
	public void testPublicKeyDERSequence() {
		System.out.println(HexString.bufferToHex(pk.getEncoded()));
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
