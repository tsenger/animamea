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
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;

import de.tsenger.animamea.asn1.AmECPublicKey;
import de.tsenger.animamea.asn1.BSIObjectIdentifiers;
import de.tsenger.animamea.asn1.DomainParameter;
import de.tsenger.animamea.tools.Converter;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class TerminalAuthenticationECDSA extends TerminalAuthentication {
	
	private ECParameterSpec ecp = null;
	private BigInteger terminalSK = null;
	private String signingAlgorithm = null;

	/**
	 * @param caDomainParameter
	 * @param ecParams
	 * @param privateKey
	 */
	public TerminalAuthenticationECDSA(DomainParameter caDomainParameter, AmECPublicKey taPublicKey, BigInteger taSecretKey) {
		
		super(caDomainParameter);
		
		ECCurve.Fp curve = (Fp) taPublicKey.getParameters().getCurve();
		ECPoint pointG = taPublicKey.getParameters().getG();
		ecp = new ECParameterSpec(curve, pointG, taPublicKey.getParameters().getN());
		
		if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_ECDSA_SHA_1.toString())) {
			signingAlgorithm = "SHA1withECDSA";
		} else if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_ECDSA_SHA_224.toString())) {
			signingAlgorithm = "SHA224withECDSA";
		} else if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_ECDSA_SHA_256.toString())) {
			signingAlgorithm = "SHA256withECDSA";
		} else if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_ECDSA_SHA_384.toString())) {
			signingAlgorithm = "SHA384withECDSA";
		} else if (taPublicKey.getOID().toString().equals(BSIObjectIdentifiers.id_TA_ECDSA_SHA_512.toString())) {
			signingAlgorithm = "SHA512withECDSA";
		}
		
		this.terminalSK = taSecretKey;
	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.ta.TerminalAuthentication#getSignature(byte[])
	 */
	@Override
	public byte[] sign(byte[] dataToSign) throws TAException {
					
		Signature sig = null;
		try {
			sig = Signature.getInstance(signingAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new TAException(e);
		}

		
		byte[] dersig = null;
		try {
			KeyFactory kef = KeyFactory.getInstance("ECDSA", "BC");
			ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(terminalSK, ecp);
			PrivateKey key = kef.generatePrivate(priKeySpec);
			sig.initSign(key); 
			sig.update(dataToSign);
			dersig = sig.sign(); 
		} catch (NoSuchAlgorithmException e) {
			throw new TAException(e);
		} catch (NoSuchProviderException e) {
			throw new TAException(e);
		} catch (InvalidKeySpecException e) {
			throw new TAException(e);
		} catch (InvalidKeyException e) {
			throw new TAException(e);
		} catch (SignatureException e) {
			throw new TAException(e);
		}

			
		// decompose signature to get r || s
		DLSequence seq = null;
		try {
			seq = (DLSequence) DLSequence.fromByteArray(dersig);
		} catch (IOException e) {
			throw new TAException(e);
		}
		ASN1Integer derIntR = (ASN1Integer) seq.getObjectAt(0);
		ASN1Integer derIntS = (ASN1Integer) seq.getObjectAt(1);
		BigInteger my_r = derIntR.getValue();
		BigInteger my_s = derIntS.getValue(); 
		
		byte[] r = Converter.bigIntToByteArray(my_r);
		byte[] s = Converter.bigIntToByteArray(my_s);
		byte[] signature = new byte[r.length+s.length];
		System.arraycopy(r, 0, signature, 0, r.length);
		System.arraycopy(s, 0, signature, r.length, s.length);
	
		return signature;
	}

	
}
