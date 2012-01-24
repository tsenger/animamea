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

import static de.tsenger.animamea.tools.Converter.bigIntToByteArray;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;

import de.tsenger.animamea.asn1.DomainParameter;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public abstract class TerminalAuthentication {
	
	private final SecureRandom randomGenerator = new SecureRandom();
	
	private BigInteger PCD_ephSK = null;
	private ECPoint PCD_ephPK_ECDH = null;
	private BigInteger PCD_ephPK_DH = null;
	
	private String dpType = null;
	
	private DomainParameter caDomainParamter = null;
	
	public TerminalAuthentication(DomainParameter caDomainParamter) {
		this.caDomainParamter = caDomainParamter;
		Security.addProvider(new BouncyCastleProvider());
		Random rnd = new Random();
		randomGenerator.setSeed(rnd.nextLong());
	}
	
	public byte[] getEphemeralPKpcd() {
		
		dpType = caDomainParamter.getDPType(); 
		
		
		if (dpType.equals("ECDH")) {
			
			ECCurve.Fp curve = (Fp) caDomainParamter.getECDHParameter().getCurve();
			ECPoint pointG = caDomainParamter.getECDHParameter().getG();
			
			byte[] rnd = new byte[(curve.getFieldSize() / 8)];
			randomGenerator.nextBytes(rnd);
			PCD_ephSK = new BigInteger(1, rnd);			
						
			PCD_ephPK_ECDH = pointG.multiply(PCD_ephSK);
			return PCD_ephPK_ECDH.getEncoded();
		}
		else if (dpType.equals("DH")) {
			
			BigInteger g = caDomainParamter.getDHParameter().getG();
			BigInteger p = caDomainParamter.getDHParameter().getP();
			
			byte[] rnd = new byte[g.bitLength() / 8];
			randomGenerator.nextBytes(rnd);
			PCD_ephSK = new BigInteger(1, rnd);
			
			PCD_ephPK_DH = g.modPow(PCD_ephSK, p);
			return bigIntToByteArray(PCD_ephPK_DH);
		}
		return null;
	}
	
	public BigInteger getSecretKey() {
		return PCD_ephSK;		
	}

	
	/**
	 * Signiert die übergebenen Daten 
	 * @param dataToSign
	 * @return
	 */
	public abstract byte[] sign(byte[] dataToSign) throws TAException;

}
