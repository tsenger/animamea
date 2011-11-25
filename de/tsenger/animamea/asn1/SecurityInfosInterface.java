package de.tsenger.animamea.asn1;

import java.util.List;

import de.tsenger.animamea.asn1.bc.CardInfoLocator;
import de.tsenger.animamea.asn1.bc.ChipAuthenticationDomainParameterInfo;
import de.tsenger.animamea.asn1.bc.ChipAuthenticationInfo;
import de.tsenger.animamea.asn1.bc.PaceDomainParameterInfo;
import de.tsenger.animamea.asn1.bc.PaceInfo;
import de.tsenger.animamea.asn1.bc.TerminalAuthenticationInfo;

/**
*
* @author Tobias Senger (tobias@t-senger.de)
*/
public interface SecurityInfosInterface {

	public byte[] getBytes();
	public List<PaceInfo> getPaceInfoList();
	public List<TerminalAuthenticationInfo> getTerminalAuthenticationInfoList();
	public List<ChipAuthenticationInfo> getChipAuthenticationInfoList();
	public List<CardInfoLocator> getCardInfoLocatorList();
	public List<ChipAuthenticationDomainParameterInfo> getChipAuthenticationDomainParameterInfoList();
	public List<PaceDomainParameterInfo> getPaceDomainParameterInfoList();
}
