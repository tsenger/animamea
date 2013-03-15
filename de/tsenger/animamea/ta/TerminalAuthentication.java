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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import de.tsenger.animamea.asn1.DomainParameter;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public abstract class TerminalAuthentication {
	
	private final SecureRandom randomGenerator = new SecureRandom();
	
	private DomainParameter caDP = null;
	
	public TerminalAuthentication(DomainParameter caDomainParameter) {
		this.caDP = caDomainParameter;
		Security.addProvider(new BouncyCastleProvider());
		Random rnd = new Random();
		randomGenerator.setSeed(rnd.nextLong());
	}

	
	public KeyPair getEphemeralPCDKeyPair() {
		ECParameterSpec ecSpec = caDP.getECParameter();
		KeyPairGenerator g = null;
		try {
			g = KeyPairGenerator.getInstance(caDP.getDPType(), "BC");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			g.initialize(ecSpec, new SecureRandom());
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		KeyPair pair = g.generateKeyPair();
		return pair;
	}


	
	/**
	 * Signiert die übergebenen Daten 
	 * @param dataToSign
	 * @return
	 */
	public abstract byte[] sign(byte[] dataToSign) throws TAException;

}
