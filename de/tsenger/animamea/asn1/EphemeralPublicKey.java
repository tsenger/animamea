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

import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_GM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_IM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

public class EphemeralPublicKey {

	private DERObjectIdentifier oid06 = null;
	private DERTaggedObject y84 = null;
	private DERTaggedObject Y86 = null;

	private DERApplicationSpecific publicKey = null;

	/**
	 * Konstruktor für EphemeralPublicKey für PACE und ChipAuthentication ->
	 * TR-03110 V2.05 Kapitel D.3.4
	 * 
	 * @param oidString
	 *            Algorithm Identifier beeinhaltet die OID des verwendeten
	 *            Algorithmus
	 * @param publicPoint
	 *            Domain Parameter des verwendeten PACE-Protokolls (für DH:
	 *            Public value (y) Tag 0x84, für ECDH: Public point (Y) Tag
	 *            0x86)
	 * @throws Exception
	 */
	public EphemeralPublicKey(String oidString, byte[] publicKeyData)
			throws Exception {

		oid06 = new DERObjectIdentifier(oidString);

		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(oid06);

		if (oidString.startsWith(id_PACE_DH_GM.toString())
				|| oidString.startsWith(id_PACE_DH_IM.toString())) {
			y84 = new DERTaggedObject(false, 4, new DEROctetString(
					publicKeyData));
			vec.add(y84);
		} else if (oidString.startsWith(id_PACE_ECDH_GM.toString())
				|| oidString.startsWith(id_PACE_ECDH_IM.toString())) {
			Y86 = new DERTaggedObject(false, 6, new DEROctetString(
					publicKeyData));
			vec.add(Y86);
		}

		else
			throw new Exception("Unknown Protocol OID");

		publicKey = new DERApplicationSpecific(0x49, vec);

	}

	/**
	 * Liefert ein ASN1-kodierted Byte-Array des PublicKeys zurück
	 * 
	 * @return
	 * @throws IOException
	 */
	public byte[] getEncoded() throws IOException {

		return publicKey.getEncoded();
	}
}