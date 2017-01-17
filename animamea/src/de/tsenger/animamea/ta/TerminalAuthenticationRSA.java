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

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;

import de.tsenger.animamea.asn1.AmRSAPublicKey;
import de.tsenger.animamea.asn1.DomainParameter;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class TerminalAuthenticationRSA extends TerminalAuthentication {
	
	private final String signingAlgorithm = null;
	private final RSAPrivateKey terminalSK = null;

	/**
	 * @param caDomainParamter
	 */
	public TerminalAuthenticationRSA(DomainParameter caDomainParamter, AmRSAPublicKey taPublicKey, RSAPrivateKey taSecretKey) {
		super(caDomainParamter);
		//TODO id_TA mit RSA implementieren.
		throw new UnsupportedOperationException("Terminal Authentication with RSA not yet implemented!");
		
//		BigInteger modulus = taPublicKey.getModulus();
//		BigInteger pubExp = taPublicKey.getPublicExponent();
//		
//		if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_RSA_PSS_SHA_1.toString())) {
//			signingAlgorithm = "SHA1withRSA";
//		} else if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_RSA_PSS_SHA_256.toString())) {
//			signingAlgorithm = "SHA256withRSA";
//		} else if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_RSA_PSS_SHA_512.toString())) {
//			signingAlgorithm = "SHA512withRSA";
//		} else if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_RSA_v1_5_SHA_1.toString())) {
//			signingAlgorithm = "SHA1withRSA";
//		} else if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_RSA_v1_5_SHA_256.toString())) {
//			signingAlgorithm = "SHA256withRSA";
//		} else if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_RSA_v1_5_SHA_512.toString())) {
//			signingAlgorithm = "SHA512withRSA";
//		}
//		
//		this.terminalSK = taSecretKey;
	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.ta.TerminalAuthentication#sign(byte[])
	 */
	@Override
	public byte[] sign(byte[] dataToSign) throws TAException {
		// TODO Auto-generated method stub
		return null;
	}

}
