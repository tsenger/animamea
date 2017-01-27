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

import static de.tsenger.animamea.tools.Converter.byteArrayToECPoint;

import java.math.BigInteger;
import java.security.PrivateKey;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPoint.Fp;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class ChipAuthenticationECDH extends ChipAuthentication {
	
	private ECPoint PK_PICC = null;
	private ECCurve.Fp curve = null;

	
	public ChipAuthenticationECDH(ECParameterSpec ecp) {
		curve  = (org.bouncycastle.math.ec.ECCurve.Fp) ecp.getCurve();

	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.ca.ChipAuthentication#getSharedSecret_K(byte[])
	 */
	@Override
	public byte[] getSharedSecret_K(PrivateKey ephskpcd, byte[] pkpicc) {
		;
		BigInteger privKey = ((ECPrivateKey)ephskpcd).getD();
		PK_PICC = byteArrayToECPoint(pkpicc, curve);
		
		ECPoint.Fp K = (Fp) PK_PICC.multiply(privKey);
//		byte[] sharedSecret_K = bigIntToByteArray(K.normalize().getXCoord().toBigInteger());
		byte[] sharedSecret_K = K.normalize().getXCoord().toBigInteger().toByteArray();
		return sharedSecret_K;
	}

}
