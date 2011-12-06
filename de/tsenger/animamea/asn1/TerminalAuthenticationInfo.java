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

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class TerminalAuthenticationInfo {

	private DERObjectIdentifier protocol = null;
	private DERInteger version = null;
	private DERSequence fileID = null;

	/**
	 * @param derSequence
	 * @throws Exception
	 *             Throws Exception if FileId is used with version 2
	 */
	public TerminalAuthenticationInfo(DERSequence seq) throws Exception {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		version = (DERInteger) seq.getObjectAt(1);
		if (seq.size() > 2) {
			fileID = (DERSequence) seq.getObjectAt(2);
		}
		if (version.getValue().intValue() == 2 && fileID != null)
			throw new Exception("FileID MUST NOT be used for version 2!");
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public int getVersion() {
		return version.getValue().intValue();
	}

	public FileID getEFCVCA() {
		if (fileID == null)
			return null; // optionales Feld FileID nicht vorhanden.
		else
			return new FileID(fileID);
	}

	@Override
	public String toString() {
		return "TerminalAuthenticationInfo\n\tOID: " + getProtocolOID()
				+ "\n\tVersion: " + getVersion() + "\n\tEF.CVCA: "
				+ getEFCVCA() + "\n";
	}

}
