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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

import de.tsenger.animamea.asn1.SecurityInfos;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CardSecurityParser {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		byte[] efcsBytes = readBinaryFile("/home/tsenger/Desktop/EFCardSecurity.bin");
		ASN1Sequence asnSeq = (ASN1Sequence) ASN1Sequence.fromByteArray(efcsBytes);
		ContentInfo contentInfo = ContentInfo.getInstance(asnSeq);
		System.out.println(contentInfo.getContentType());
		DERSequence derSeq = (DERSequence) contentInfo.getContent();
		System.out.println(HexString.bufferToHex(derSeq.getEncoded(null)));
		SignedData signedData = SignedData.getInstance(derSeq);
		System.out.println("CMSVersion: "+signedData.getVersion().getValue().intValue());
		ContentInfo contentInfo2 = signedData.getEncapContentInfo();
		System.out.println(contentInfo2.getContentType());
		DEROctetString octString = (DEROctetString) contentInfo2.getContent();
		System.out.println("OctetString:\n"+HexString.bufferToHex(octString.getEncoded(null)));
		System.out.println("OctetString:\n"+HexString.bufferToHex(octString.getOctets()));
		
		SecurityInfos si = new SecurityInfos();
		si.decode(octString.getOctets());
		System.out.println(si);
		
		byte[] parameter = si.getChipAuthenticationPublicKeyInfoList().get(0).getPublicKey().getPublicKey();
		System.out.println(HexString.bufferToHex(parameter));
		System.out.println("Key Referenz: "+si.getChipAuthenticationPublicKeyInfoList().get(0).getKeyId());
		System.out.println("id_CA OID: "+si.getChipAuthenticationPublicKeyInfoList().get(0).getPublicKey().getAlgorithm().getAlgorithm());

	}
	
	private static byte[] readBinaryFile(String filename) {
		FileInputStream in = null;
		File efCardAccessFile = new File(filename);
		byte buffer[] = new byte[(int) efCardAccessFile.length()	];

		try {
			in = new FileInputStream(efCardAccessFile);
			in.read(buffer, 0, buffer.length);
			in.close();
		} catch (FileNotFoundException ex) {
		} catch (IOException ex) {
		}

		return buffer;
	}

}
