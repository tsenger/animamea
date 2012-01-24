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

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

/**
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 */

public class SecurityInfos {

	List<TerminalAuthenticationInfo> terminalAuthenticationInfoList = new ArrayList<TerminalAuthenticationInfo>();
	List<ChipAuthenticationInfo> chipAuthenticationInfoList = new ArrayList<ChipAuthenticationInfo>();
	List<PaceInfo> paceInfoList = new ArrayList<PaceInfo>();
	List<PaceDomainParameterInfo> paceDomainParameterInfoList = new ArrayList<PaceDomainParameterInfo>();
	List<ChipAuthenticationDomainParameterInfo> chipAuthenticationDomainParameterInfoList = new ArrayList<ChipAuthenticationDomainParameterInfo>();
	List<CardInfoLocator> cardInfoLocatorList = new ArrayList<CardInfoLocator>();
	List<PrivilegedTerminalInfo> privilegedTerminalInfoList = new ArrayList<PrivilegedTerminalInfo>();
	List<ChipAuthenticationPublicKeyInfo> chipAuthenticationPublicKeyInfoList = new ArrayList<ChipAuthenticationPublicKeyInfo>();

	private byte[] encodedData = null;

	public SecurityInfos() {
	}

	/* *
	 * Decodes the byte array passed as argument. The decoded values are stored
	 * in the member variables of this class that represent the components of
	 * the corresponding ASN.1 type.
	 * 
	 * @param encodedData DOCUMENT ME!
	 * 
	 * @ throws IOException DOCUMENT ME!
	 */
	public void decode(byte[] encodedData) throws Exception {
		this.encodedData = encodedData;
		ASN1Set securityInfos = (ASN1Set) ASN1Object.fromByteArray(encodedData);
		int anzahlObjekte = securityInfos.size();
		DERSequence securityInfo[] = new DERSequence[anzahlObjekte];

		for (int i = 0; i < anzahlObjekte; i++) {
			securityInfo[i] = (DERSequence) securityInfos.getObjectAt(i);
			DERObjectIdentifier oid = (DERObjectIdentifier) securityInfo[i]
					.getObjectAt(0);

			switch (oid.toString().charAt(18)) {
			case '1': 
				chipAuthenticationPublicKeyInfoList.add(new ChipAuthenticationPublicKeyInfo(securityInfo[i]));
				break;
			case '2':
				terminalAuthenticationInfoList.add(new TerminalAuthenticationInfo(securityInfo[i]));
				break;
			case '3':
				if (oid.toString().length() == 23)
					chipAuthenticationInfoList.add(new ChipAuthenticationInfo(securityInfo[i]));
				else
					chipAuthenticationDomainParameterInfoList.add(new ChipAuthenticationDomainParameterInfo(securityInfo[i]));
				break;
			case '4':
				if (oid.toString().length() == 23)
					paceInfoList.add(new PaceInfo(securityInfo[i]));
				else
					paceDomainParameterInfoList.add(new PaceDomainParameterInfo(securityInfo[i]));
				break;
			case '6':
				cardInfoLocatorList.add(new CardInfoLocator(securityInfo[i]));
				break;
			case '8':
				privilegedTerminalInfoList.add(new PrivilegedTerminalInfo(securityInfo[i]));
				break;
			} // SWITCH

		} // IF

	}

	@Override
	public String toString() {
		String summary = null;
		summary = "------------------\nSecurityInfos object contains\n"
				+ terminalAuthenticationInfoList.size()
				+ " TerminalAuthenticationInfo objects \n"
				+ chipAuthenticationInfoList.size()
				+ " ChipAuthenticationInfo objects \n"
				+ chipAuthenticationDomainParameterInfoList.size()
				+ " ChipAuthenticationDomainParameterInfo objects \n"
				+ chipAuthenticationPublicKeyInfoList.size()
				+ " ChipAuthenticationPublicKeyInfo objects \n"
				+ paceInfoList.size() + " PaceInfo objects \n"
				+ paceDomainParameterInfoList.size()
				+ " PaceDomainParameterInfo objects \n"
				+ cardInfoLocatorList.size() + " CardInfoLocator objects \n"
				+ privilegedTerminalInfoList.size()
				+ " PrivilegedTerminalInfo objects\n------------------\n";

		for (TerminalAuthenticationInfo item : terminalAuthenticationInfoList) {
			summary = summary + item.toString();
		}
		for (ChipAuthenticationInfo item : chipAuthenticationInfoList) {
			summary = summary + item.toString();
		}
		for (ChipAuthenticationDomainParameterInfo item : chipAuthenticationDomainParameterInfoList) {
			summary = summary + item.toString();
		}
		for (ChipAuthenticationPublicKeyInfo item : chipAuthenticationPublicKeyInfoList) {
			summary = summary + item.toString();
		}
		for (PaceInfo item : paceInfoList) {
			summary = summary + item.toString();
		}
		for (PaceDomainParameterInfo item : paceDomainParameterInfoList) {
			summary = summary + item.toString();
		}
		for (CardInfoLocator item : cardInfoLocatorList) {
			summary = summary + item.toString();
		}
		for (PrivilegedTerminalInfo item : privilegedTerminalInfoList) {
			summary = summary + item.toString();
		}

		return summary;
	}

	public byte[] getBytes() {
		return encodedData;
	}

	public List<PaceInfo> getPaceInfoList() {
		return paceInfoList;
	}

	public List<TerminalAuthenticationInfo> getTerminalAuthenticationInfoList() {
		return terminalAuthenticationInfoList;
	}

	public List<ChipAuthenticationInfo> getChipAuthenticationInfoList() {
		return chipAuthenticationInfoList;
	}

	public List<CardInfoLocator> getCardInfoLocatorList() {
		return cardInfoLocatorList;
	}

	public List<ChipAuthenticationDomainParameterInfo> getChipAuthenticationDomainParameterInfoList() {
		return chipAuthenticationDomainParameterInfoList;
	}

	public List<PaceDomainParameterInfo> getPaceDomainParameterInfoList() {
		return paceDomainParameterInfoList;
	}
	
	public List<ChipAuthenticationPublicKeyInfo> getChipAuthenticationPublicKeyInfoList() {
		return chipAuthenticationPublicKeyInfoList;
	}

}
