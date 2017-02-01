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

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;

import de.tsenger.animamea.asn1.CVCertificate;
import de.tsenger.animamea.tools.FileSystem;

/**
 * Hart verdrahteter Provider für id_TA-Zertifikate
 * 
 * Hier gibt's noch was zu tun ;)
 * 
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CertificateProvider {
	
	private final byte[] cvcaBytes;
	private final byte[] dvBytes;
	private final byte[] atBytes;
	private final byte[] pkBytes;
	
	public CertificateProvider(String cvcaCertFilename, String dvCertFilename, String terminalCertFilename, String privateKeyFilename) throws IOException {
		cvcaBytes = FileSystem.readFile(cvcaCertFilename);
		dvBytes = FileSystem.readFile(dvCertFilename);
		atBytes = FileSystem.readFile(terminalCertFilename);
		pkBytes = FileSystem.readFile(privateKeyFilename);
	}
	
	
	public CVCertificate getCVCACert() throws IllegalArgumentException, IOException {
		CVCertificate cert = null;
		cert = new CVCertificate(cvcaBytes);
		return cert;
	}
	
	public CVCertificate getDVCert() throws IllegalArgumentException, IOException {
		CVCertificate cert = null;
		cert = new CVCertificate(dvBytes);
		return cert;
	}
	
	public CVCertificate getTerminalCert() throws IllegalArgumentException, IOException {
		CVCertificate cert = null;
		cert = new CVCertificate(atBytes);
		return cert;
	}
	
	public ECPrivateKey getPrivateKey() throws IOException {
		ASN1Sequence pkSeq = null;
		pkSeq = (ASN1Sequence) ASN1Sequence.fromByteArray(pkBytes);
		
		PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(pkSeq);
		ECPrivateKey ecpk = ECPrivateKey.getInstance(pkInfo.parsePrivateKey());
		return ecpk;
	}

}
