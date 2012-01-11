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
package de.tsenger.sandbox;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;

import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class PKCS8PrivateKey {
	
	public static void main(String[] args) throws IOException {
		byte[] pkBytes = readBinaryFile("/home/tsenger/Dokumente/Programming/animamea/certs/Key_DEATTIDBSIDE003.pkcs8");
		
		DERSequence pkSeq =  (DERSequence) DERSequence.fromByteArray(pkBytes);
		
		PrivateKeyInfo pk = new PrivateKeyInfo(pkSeq);
		
		 AlgorithmIdentifier ecPublicKey = pk.getAlgorithmId();
		 
		 System.out.println(ecPublicKey.getAlgorithm().toString());
		 System.out.println(HexString.bufferToHex(ecPublicKey.getDEREncoded()));
		 
		 X9ECParameters ecp = new X9ECParameters((ASN1Sequence) ecPublicKey.getParameters());
		 
		 System.out.println("H: "+ecp.getN());
		
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
