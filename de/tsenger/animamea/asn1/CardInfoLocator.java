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

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

;

/**
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 */
public class CardInfoLocator {

	private DERObjectIdentifier protocol = null;
	private DERIA5String url = null;
	private DERSequence fileID = null;

	public CardInfoLocator(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		url = (DERIA5String) seq.getObjectAt(1);
		if (seq.size() > 2) {
			fileID = (DERSequence) seq.getObjectAt(2);
		}
	}

	public String getOID() {
		return protocol.getId();
	}

	public String getUrl() {
		return url.getString();
	}

	public FileID getFileID() {
		if (fileID == null)
			return null;
		else
			return new FileID(fileID);
	}

	@Override
	public String toString() {
		return "CardInfoLocator \n\tOID: " + getOID() + "\n\tURL: " + getUrl()
				+ "\n\t" + getFileID() + "\n";

	}

}
