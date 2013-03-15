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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class Pace_new {
	
	private byte[] nonce_s = null;
	private final byte[] sharedSecret_P = null;
	private final byte[] sharedSecret_K = null;
	
	private PrivateKey PCD_SK_x1 = null;
	private PublicKey PCD_PK_X1 = null;
	
	private PublicKey PICC_PK_Y1;
	
	private PrivateKey PCD_SK_x2 = null;
	private PublicKey PCD_PK_X2 = null;
	
	private String algorithm = null;
	
	private AlgorithmParameterSpec aps = null;
	
	
	
	public Pace_new(AlgorithmParameterSpec aps) {
		this.aps = aps;
		if (aps instanceof ECParameterSpec) {
			algorithm = "ECDH";
		} else if (aps instanceof DHParameters) {
			algorithm = "DH";
		}
	} 
	
	private KeyPair getKeyPair() {
		KeyPairGenerator g = null;
		try {
			g = KeyPairGenerator.getInstance(algorithm, "BC");
			g.initialize(aps, new SecureRandom());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		KeyPair pair = g.generateKeyPair();
		return pair;
	}

	public PublicKey getX1(byte[] s) {
		nonce_s = s;
		KeyPair kp = getKeyPair();
		PCD_PK_X1 = kp.getPublic();
		PCD_SK_x1 = kp.getPrivate();
		return PCD_PK_X1;
	}
	
	public PublicKey getX2(PublicKey Y1) {
		PICC_PK_Y1 = Y1;
		calculateSharedSecretP(); // berechnet P
		calculateNewPointG(); // berechnet G'
		byte[] x2 = new byte[(curve.getFieldSize() / 8)];
		randomGenerator.nextBytes(x2);
		PCD_SK_x2 = new BigInteger(1, x2);
		PCD_PK_X2 = pointG_strich.multiply(PCD_SK_x2);
		return PCD_PK_X2;
		return null;
	}
	
	public byte[] getSharedSecret_K(PublicKey Y2) {
		return null;
	}
	
	/**
	 * Erzeugt aus dem Public Key 1 der Karte (PICC_PK_Y1) und dem Secret Key
	 * PCD_SK_x1 das erste Shared Secret P
	 */
	private void calculateSharedSecretP() {
		SharedSecret_P = PICC_PK_Y1.multiply(PCD_SK_x1);
		
		SharedSecret_P = PICC_PK_Y1.modPow(PCD_SK_x1, p);
	}
}
