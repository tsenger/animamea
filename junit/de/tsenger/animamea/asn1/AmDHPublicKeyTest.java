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
package junit.de.tsenger.animamea.asn1;

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import de.tsenger.animamea.asn1.AmDHPublicKey;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class AmDHPublicKeyTest {
	AmDHPublicKey pk = null;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		pk = new AmDHPublicKey("0.4.0.127.2.2.3.2.2.2", new BigInteger("11111111",16), new BigInteger("22222222",16), new BigInteger("33333333",16), new BigInteger("44444444",16));
	}

	/**
	 * Test method for {@link de.tsenger.animamea.asn1.AmDHPublicKey#getEncoded()}.
	 */
	@Test
	public void testGetEncoded() {
		System.out.println(HexString.bufferToHex(pk.getEncoded()));
	}


}
