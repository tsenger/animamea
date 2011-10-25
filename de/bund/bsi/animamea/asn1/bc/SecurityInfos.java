package de.bund.bsi.animamea.asn1.bc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

import de.bund.bsi.animamea.asn1.SecurityInfosInterface;

/**
 * 
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 */

//TODO Klasse um Prüfung aller in der TR-03110 genannten Bedingungen erweitern. (z.B. max 1 CardInfoLocator)
public class SecurityInfos implements SecurityInfosInterface {

	List<TerminalAuthenticationInfo> terminalAuthenticationInfoList = new ArrayList<TerminalAuthenticationInfo>();
	List<ChipAuthenticationInfo> chipAuthenticationInfoList = new ArrayList<ChipAuthenticationInfo>();
	List<PaceInfo> paceInfoList = new ArrayList<PaceInfo>();
	List<PaceDomainParameterInfo> paceDomainParameterInfoList = new ArrayList<PaceDomainParameterInfo>();
	List<ChipAuthenticationDomainParameterInfo> chipAuthenticationDomainParameterInfoList = new ArrayList<ChipAuthenticationDomainParameterInfo>();
	List<CardInfoLocator> cardInfoLocatorList = new ArrayList<CardInfoLocator>();

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
	public void decode(byte[] encodedData) throws IOException {
		this.encodedData = encodedData;
		ASN1Set securityInfos = (ASN1Set) ASN1Object.fromByteArray(encodedData);
		int anzahlObjekte = securityInfos.size();
		DERSequence securityInfo[] = new DERSequence[anzahlObjekte];

		for (int i = 0; i < anzahlObjekte; i++) {
			securityInfo[i] = (DERSequence) securityInfos.getObjectAt(i);
			DERObjectIdentifier oid = (DERObjectIdentifier) securityInfo[i]
					.getObjectAt(0);
			switch (oid.toString().charAt(18)) { //TODO Besser auf komplette OID prüfen
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
			} // SWITCH

		} // IF

	}

	@Override
	public String toString() {
		String summary = null;
		summary = "SecurityInfos object contains\n"
				+ terminalAuthenticationInfoList.size()
				+ " TerminalAuthenticationInfo objects \n"
				+ chipAuthenticationInfoList.size()
				+ " ChipAuthenticationInfo objects \n"
				+ chipAuthenticationDomainParameterInfoList.size()
				+ " ChipAuthenticationDomainParameterInfo objects \n"
				+ paceInfoList.size() + " PaceInfo objects \n"
				+ paceDomainParameterInfoList.size()
				+ " PaceDomainParameterInfo objects \n"
				+ cardInfoLocatorList.size() + " CardInfoLocator objects \n";
		return summary;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.bund.bsi.animamea.asn1.SecurityInfosInterface#getBytes()
	 */
	@Override
	public byte[] getBytes() {
		return encodedData;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.bund.bsi.animamea.asn1.SecurityInfosInterface#getPaceInfoList()
	 */
	@Override
	public List<PaceInfo> getPaceInfoList() {
		return paceInfoList;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.bund.bsi.animamea.asn1.SecurityInfosInterface#
	 * getTerminalAuthenticationInfoList()
	 */
	@Override
	public List<TerminalAuthenticationInfo> getTerminalAuthenticationInfoList() {
		return terminalAuthenticationInfoList;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * de.bund.bsi.animamea.asn1.SecurityInfosInterface#getChipAuthenticationInfoList
	 * ()
	 */
	@Override
	public List<ChipAuthenticationInfo> getChipAuthenticationInfoList() {
		return chipAuthenticationInfoList;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * de.bund.bsi.animamea.asn1.SecurityInfosInterface#getCardInfoLocatorList()
	 */
	@Override
	public List<CardInfoLocator> getCardInfoLocatorList() {
		return cardInfoLocatorList;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.bund.bsi.animamea.asn1.SecurityInfosInterface#
	 * getChipAuthenticationDomainParameterInfoList()
	 */
	@Override
	public List<ChipAuthenticationDomainParameterInfo> getChipAuthenticationDomainParameterInfoList() {
		return chipAuthenticationDomainParameterInfoList;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * de.bund.bsi.animamea.asn1.SecurityInfosInterface#getPaceDomainParameterInfoList
	 * ()
	 */
	@Override
	public List<PaceDomainParameterInfo> getPaceDomainParameterInfoList() {
		return paceDomainParameterInfoList;
	}

}
