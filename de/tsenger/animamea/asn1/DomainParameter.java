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
package de.tsenger.animamea.asn1;

import static de.tsenger.animamea.pace.DHStandardizedDomainParameters.modp1024_160;
import static de.tsenger.animamea.pace.DHStandardizedDomainParameters.modp2048_224;
import static de.tsenger.animamea.pace.DHStandardizedDomainParameters.modp2048_256;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.DHParameters;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class DomainParameter {
	
	private DHParameters dhParameters = null;
	private X9ECParameters ecdhParameters = null;
	
	/**
	 * Extrahiert aus dem AlogorithmIdentifier die Parameter für EH oder ECDH.
	 * Es werden standardisierte DomainParameter und explizite DP erkannt.
	 * TODO explizite DH Parameter werden noch nicht erkannt. 
	 * @param algorithm OID
	 * @param ref Referenz auf einen Domain Parameter
	 */
	public DomainParameter(AlgorithmIdentifier aid) {
		if (aid.getAlgorithm().toString().equals(BSIObjectIdentifiers.standardizedDomainParameters.toString())) {
			
			int dpref = ((DERInteger)aid.getParameters()).getPositiveValue().intValue(); 
			
			switch (dpref) {
			case 0:
				dhParameters = modp1024_160();
				break;
			case 1:
				dhParameters = modp2048_224();
				break;
			case 3:
				dhParameters = modp2048_256();
				break;
			case 8:
				ecdhParameters = SECNamedCurves.getByName("secp192r1");
				break;
			case 9:
				ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp192r1");
				break;
			case 10:
				ecdhParameters = SECNamedCurves.getByName("secp224r1");
				break;
			case 11:
				ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp224r1");
				break;
			case 12:
				ecdhParameters = SECNamedCurves.getByName("secp256r1");
				break;
			case 13:
				ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp256r1");
				break;
			case 14:
				ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp320r1");
				break;
			case 15:
				ecdhParameters = SECNamedCurves.getByName("secp384r1");
				break;
			case 16:
				ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp384r1");
				break;
			case 17:
				ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp512r1");
				break;
			case 18:
				ecdhParameters = SECNamedCurves.getByName("secp521r1");
				break;
			}	
		}
		
		else if (aid.getAlgorithm().toString().equals(BSIObjectIdentifiers.id_ecPublicKey)) {
			ecdhParameters = new X9ECParameters((ASN1Sequence) aid.getParameters());
		}
		
		else throw new UnsupportedOperationException("unsupported Domain Parameters");
	}
	
	public String getDPType() {
		if (ecdhParameters!=null) return "ECDH";
		else if (dhParameters!=null) return "DH";
		return null;
	}
	
	public X9ECParameters getECDHParameter() {
		return ecdhParameters;
	}
	
	public DHParameters getDHParameter() {
		return dhParameters;
	}

}
