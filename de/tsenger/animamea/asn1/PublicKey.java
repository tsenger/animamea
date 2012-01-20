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
package de.tsenger.animamea.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

/**
 * Abstrakte Klasse für Public Key Data Objects 
 * nach BSI TR-03110 V2.05 Kapitel D.3.
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public abstract class PublicKey implements java.security.PublicKey{
	

	private static final long serialVersionUID = -7727955941480920278L;
	
	private DERObjectIdentifier oid06 = null;
	protected ASN1EncodableVector vec = new ASN1EncodableVector();

	/**
	 * Konstruktor zum Encoden
	 * 
	 * @param oidString
	 *            Algorithm Identifier beeinhaltet die OID des verwendeten
	 *            Algorithmus
	 */
	public PublicKey(String oidString) {
		oid06 = new DERObjectIdentifier(oidString);
		vec.add(oid06);
	}
	
	/**
	 * Konstruktur zum Decoden
	 * @param seq ASN1 Sequenz welche die Public Key Struktur enthält.
	 */
	public PublicKey(DERSequence seq) {
		oid06 = (DERObjectIdentifier) seq.getObjectAt(0);		
		vec.add(oid06);
	}
	
	/**
	 * Extrahiert aus der übergebenen DERSequence die Daten des Public Keys Objects.
	 * 
	 * @param seq
	 */
	protected abstract void decode(DERSequence seq);

	
	/**
	 * Liefert ein ASN1-kodierted Byte-Array des PublicKeys zurück
	 * 
	 * @return
	 */
	protected byte[] getDEREncoded() {
		DERApplicationSpecific publicKey = new DERApplicationSpecific(0x49, vec);
		return publicKey.getDEREncoded();
	}
	
	public String getOID() {
		return oid06.toString();
	}

}
