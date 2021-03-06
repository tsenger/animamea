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

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public abstract class Pace {

	/**
	 * Berechnet das erste KeyPair. x1: privater Schlüssel (Zufallszahl) und X1:
	 * öffentlicher Schlüssel.
	 * 
	 * @param s
	 *            Die enschlüsselte nonce s der Karte
	 * @return Der erste öffentliche Schlüssel X1 des Terminals.
	 */
	public abstract byte[] getX1(byte[] s);

	/**
	 * Berechnet mit Hilfe des öffentlichen Schlüssels der Karte das erste
	 * Shared Secret P und den zweiten öffentlichen Schlüssel des Terminals
	 * 
	 * @param Y1
	 *            Erster öffentlicher Schlüssel der Karte.
	 * @return Zweiter öffentlicher Schlüssel X2 des Terminals.
	 */
	public abstract byte[] getX2(byte[] Y1);

	/**
	 * Erzeugt das finale Shared Secret K
	 * 
	 * @param Y2
	 *            Zweiter öffentlicher Schlüssel Y2 der Karte
	 * 
	 */
	public abstract byte[] getSharedSecret_K(byte[] Y2);

}
