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

import de.tsenger.animamea.crypto.KeyDerivationFunction;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class KDFTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		byte[] key = null;
		byte[] passwordBytes = "123456".getBytes();
		
		KeyDerivationFunction kdf = new KeyDerivationFunction(passwordBytes, 3);
		key = kdf.getAES128Key();
		
		System.out.println (HexString.bufferToHex(key));

	}

}
