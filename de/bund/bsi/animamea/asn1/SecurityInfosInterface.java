package de.bund.bsi.animamea.asn1;

import java.util.List;

import de.bund.bsi.animamea.asn1.bc.CardInfoLocator;
import de.bund.bsi.animamea.asn1.bc.ChipAuthenticationDomainParameterInfo;
import de.bund.bsi.animamea.asn1.bc.ChipAuthenticationInfo;
import de.bund.bsi.animamea.asn1.bc.PaceDomainParameterInfo;
import de.bund.bsi.animamea.asn1.bc.PaceInfo;
import de.bund.bsi.animamea.asn1.bc.TerminalAuthenticationInfo;

/**
*
* @author Tobias Senger (tobias.senger@bsi.bund.de)
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
