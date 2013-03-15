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

import java.security.PrivateKey;

import org.bouncycastle.crypto.params.DHParameters;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class ChipAuthenticationDH extends ChipAuthentication {
	
	private DHParameters dp = null;
	
	public ChipAuthenticationDH(DHParameters dp) {
		
		this.dp = dp;
		
	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.ca.ChipAuthentication#getSharedSecret_K(java.math.BigInteger, byte[])
	 */
	@Override
	public byte[] getSharedSecret_K(PrivateKey ephskpcd, byte[] pkpicc) {
		// TODO Auto-generated method stub
		return null;
	}

}
