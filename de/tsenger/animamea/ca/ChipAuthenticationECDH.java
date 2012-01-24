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
package de.tsenger.animamea.ca;

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
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class ChipAuthenticationECDH extends ChipAuthentication {
	
	private final ECPoint ephSK_PCD = null;
	private ECPoint PK_PICC = null;
	private ECPoint pointG = null;
	private ECCurve.Fp curve = null;
	
	private final SecureRandom randomGenerator = new SecureRandom();
	
	
	public ChipAuthenticationECDH(X9ECParameters cp) {
		pointG  = cp.getG();
		curve  = (org.bouncycastle.math.ec.ECCurve.Fp) cp.getCurve();
		Random rnd = new Random();
		randomGenerator.setSeed(rnd.nextLong());
	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.ca.ChipAuthentication#getSharedSecret_K(byte[])
	 */
	@Override
	public byte[] getSharedSecret_K(BigInteger ephskpcd, byte[] pkpicc) {
		PK_PICC = byteArrayToECPoint(pkpicc, curve);
		
		ECPoint.Fp K = (Fp) PK_PICC.multiply(ephskpcd);
		byte[] sharedSecret_K = bigIntToByteArray(K.getX().toBigInteger());
		return sharedSecret_K;
	}

}
