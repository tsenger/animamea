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

package de.tsenger.animamea.pace;

import static de.tsenger.animamea.tools.Converter.bigIntToByteArray;
import static de.tsenger.animamea.tools.Converter.byteArrayToECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPoint.Fp;

/**
 * PACE mit Elliptic Curve Diffie Hellman
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */

public class PaceECDH extends Pace {

	private ECPoint pointG = null;
	private ECPoint pointG_strich = null;
	private ECCurve.Fp curve = null;
	private final SecureRandom randomGenerator = new SecureRandom();

	private BigInteger PCD_SK_x1 = null;
	private ECPoint PCD_PK_X1 = null;

	private BigInteger PCD_SK_x2 = null;
	private ECPoint PCD_PK_X2 = null;

	private ECPoint PICC_PK_Y1 = null;
	private ECPoint PICC_PK_Y2 = null;

	private ECPoint.Fp SharedSecret_P = null;

	public PaceECDH(X9ECParameters cp) {

		pointG = cp.getG();
		curve = (org.bouncycastle.math.ec.ECCurve.Fp) cp.getCurve();
		Random rnd = new Random();
		randomGenerator.setSeed(rnd.nextLong());

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.pace.Pace#getX1(byte[])
	 */
	@Override
	public byte[] getX1(byte[] s) {
		nonce_s = s;
		byte[] x1 = new byte[(curve.getFieldSize() / 8)];
		randomGenerator.nextBytes(x1);
		PCD_SK_x1 = new BigInteger(1, x1);
		// PCD_SK_x1 = new BigInteger("752287F5B02DE3C4BC3E17945118C51B" +
		// "23C97278E4CD748048AC56BA5BDC3D46",16);
		PCD_PK_X1 = pointG.multiply(PCD_SK_x1);
		return PCD_PK_X1.getEncoded();
	}

	/**
	 * Berechnet mit Hilfe des öffentlichen Schlüssels der Karte das erste
	 * Shared Secret P, den neuen Punkt G', sowie den zweiten öffentlichen
	 * Schlüssels des Terminals (X2 = x2 * G').
	 * 
	 * @param Y1
	 *            Erster öffentlicher Schlüssel der Karte
	 * @return Zweiter öffentlicher Schlüssel X2 des Terminals.
	 */
	private ECPoint getX2(ECPoint.Fp Y1) {
		PICC_PK_Y1 = Y1;
		calculateSharedSecretP(); // berechnet P
		calculateNewPointG(); // berechnet G'
		byte[] x2 = new byte[(curve.getFieldSize() / 8)];
		randomGenerator.nextBytes(x2);
		PCD_SK_x2 = new BigInteger(1, x2);
		// PCD_SK_x2 = new BigInteger("9D9A32DF93A57CCE33CA3CDD3457E33A" +
		// "976F293546C73550F397259C93BE0120",16);
		PCD_PK_X2 = pointG_strich.multiply(PCD_SK_x2);
		return PCD_PK_X2;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.pace.Pace#getX2(byte[])
	 */
	@Override
	public byte[] getX2(byte[] Y1Bytes) {
		ECPoint.Fp Y1 = null;
		try {
			Y1 = (Fp) byteArrayToECPoint(Y1Bytes, curve);
		} catch (Exception e) {
			System.err.println(e.toString());
			e.printStackTrace();
		}
		return getX2(Y1).getEncoded();
	}

	/**
	 * Erzeugt aus dem Public Key 1 der Karte (PICC_PK_Y1) und dem Secret Key
	 * PCD_SK_x1 das erste Shared Secret P
	 * 
	 */
	private void calculateSharedSecretP() {
		SharedSecret_P = (Fp) PICC_PK_Y1.multiply(PCD_SK_x1);
		sharedSecret_P = SharedSecret_P.getEncoded();
	}

	/**
	 * Erzeugt aus der nonce s, dem Punkt G und dem shared secret P den neuen
	 * Punkt G' G' = s*G+P
	 * 
	 * @throws Exception
	 *             Falls nonce s noch nicht berechnet wurde (passiert während
	 *             getX1) wird diese Exception geworfen
	 */
	private void calculateNewPointG() {

		BigInteger ms = new BigInteger(1, nonce_s);
		ECPoint g_temp = pointG.multiply(ms);
		pointG_strich = g_temp.add(SharedSecret_P);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.pace.Pace#getSharedSecret_K(byte[])
	 */
	@Override
	public byte[] getSharedSecret_K(byte[] Y2) {
		try {
			PICC_PK_Y2 = byteArrayToECPoint(Y2, curve);
		} catch (Exception e) {
			System.err.println(e.toString());
			e.printStackTrace();
		}
		ECPoint.Fp K = (Fp) PICC_PK_Y2.multiply(PCD_SK_x2);
		sharedSecret_K = bigIntToByteArray(K.getX().toBigInteger());
		return sharedSecret_K;
	}

}
