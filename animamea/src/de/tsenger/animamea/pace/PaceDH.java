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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.crypto.params.DHParameters;

/**
 * id_PACE mit Diffie Hellman
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class PaceDH extends Pace {

	private final SecureRandom randomGenerator = new SecureRandom();
	private BigInteger g = null;
	private BigInteger p = null;

	private BigInteger PCD_SK_x1 = null;
	private BigInteger PCD_SK_x2 = null;

	private byte[] nonce_s = null;

	public PaceDH(DHParameters dhParameters) {
		g = dhParameters.getG();
		p = dhParameters.getP();
		Random rnd = new Random();
		randomGenerator.setSeed(rnd.nextLong());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.pace.Pace#getX1()
	 */
	@Override
	public byte[] getX1(byte[] s) {
		nonce_s  = s.clone();
		
		byte[] x1 = new byte[g.bitLength() / 8];
		randomGenerator.nextBytes(x1);
		PCD_SK_x1 = new BigInteger(1, x1);
		
		BigInteger PCD_PK_X1 = g.modPow(PCD_SK_x1, p);
		
		return bigIntToByteArray(PCD_PK_X1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.pace.Pace#getX2(byte[])
	 */
	@Override
	public byte[] getX2(byte[] Y1) {
		BigInteger PICC_PK_Y1 = new BigInteger(1, Y1);
		
		BigInteger SharedSecret_P = PICC_PK_Y1.modPow(PCD_SK_x1, p);
		
		BigInteger g_strich = g.modPow(new BigInteger(1, nonce_s), p).multiply(SharedSecret_P).mod(p);
		
		byte[] x2 = new byte[g.bitLength() / 8];
		randomGenerator.nextBytes(x2);
		PCD_SK_x2 = new BigInteger(1, x2);
		
		BigInteger PCD_PK_X2 = g_strich.modPow(PCD_SK_x2, p);
		
		return bigIntToByteArray(PCD_PK_X2);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.tsenger.animamea.pace.Pace#getK(byte[])
	 */
	@Override
	public byte[] getSharedSecret_K(byte[] Y2) {
		BigInteger PICC_PK_Y2 = new BigInteger(1, Y2);
		BigInteger SharedSecret_K = PICC_PK_Y2.modPow(PCD_SK_x2, p);
		return bigIntToByteArray(SharedSecret_K);
	}

}
