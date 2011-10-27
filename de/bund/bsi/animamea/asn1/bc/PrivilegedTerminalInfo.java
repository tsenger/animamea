/**
 * 
 */
package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

import de.bund.bsi.animamea.asn1.PrivilegedTerminalInfoInterface;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class PrivilegedTerminalInfo implements PrivilegedTerminalInfoInterface{

	private DERObjectIdentifier protocol = null;
	private SecurityInfos secinfos = null;

	public PrivilegedTerminalInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		secinfos = (SecurityInfos)seq.getObjectAt(1);
	}
	
	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.PrivilegedTerminalInfoInterface#getProtocolOID()
	 */
	@Override
	public String getProtocolOID() {
		return protocol.getId();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.PrivilegedTerminalInfoInterface#getSecurityInfos()
	 */
	@Override
	public SecurityInfos getSecurityInfos() {
		return secinfos;
	}
	
	@Override
	public String toString() {
		return "PrivilegedTerminalInfo\n\tOID: " + getProtocolOID() + "\n\tSecurityInfos: " + getSecurityInfos() + "\n";
	}

}
