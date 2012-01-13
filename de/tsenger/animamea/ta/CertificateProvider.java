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
package de.tsenger.animamea.ta;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

import de.tsenger.animamea.asn1.CVCertificate;
import de.tsenger.animamea.asn1.ECPrivateKey;

/**
 * Hart verdrahteter Provider für TA-Zertifikate
 * 
 * Hier gibt's noch was zu tun ;)
 * 
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CertificateProvider {
	
	public CVCertificate getDVCert() throws IllegalArgumentException, IOException {
		byte[] dvBytes = readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/certs/DV_DEDVTIDBSIDE003_DETESTeID00002.cvcert");
		return new CVCertificate(dvBytes);
	}
	
	public CVCertificate getTerminalCert() throws IllegalArgumentException, IOException {
		byte[] atBytes = readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/certs/AT_DEATTIDBSIDE003_DEDVTIDBSIDE003.cvcert");
		return new CVCertificate(atBytes);
	}
	
	public ECPrivateKey getPrivateKey() throws IOException {
		byte[] pkBytes = readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/certs/Key_DEATTIDBSIDE003.pkcs8");
		DERSequence pkSeq =  (DERSequence) DERSequence.fromByteArray(pkBytes);
		PrivateKeyInfo pkInfo = new PrivateKeyInfo(pkSeq);
		ECPrivateKey ecpk = ECPrivateKey.getInstance(pkInfo.getPrivateKey());
		return ecpk;
	}
	
	private static byte[] readBinaryFile(String filename) {
		FileInputStream in = null;
		File efCardAccessFile = new File(filename);
		byte buffer[] = new byte[(int) efCardAccessFile.length()	];

		try {
			in = new FileInputStream(efCardAccessFile);
			in.read(buffer, 0, buffer.length);
		} catch (FileNotFoundException ex) {
		} catch (IOException ex) {
		}

		return buffer;
	}

}
