/**
 * 
 */
package de.tsenger.animamea.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class PrivilegedTerminalInfo {

	private DERObjectIdentifier protocol = null;
	private SecurityInfos secinfos = null;

	public PrivilegedTerminalInfo(DERSequence seq) throws IOException, Exception {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		
		DERSet derSet = (DERSet) seq.getObjectAt(1);
		
		SecurityInfos si = new SecurityInfos();
		si.decode(derSet.getEncoded());
		
		secinfos = (si);
	}
	

	public String getProtocolOID() {
		return protocol.getId();
	}


	public SecurityInfos getSecurityInfos() {
		return secinfos;
	}
	
	@Override
	public String toString() {
		return "PrivilegedTerminalInfo\n\tOID: " + getProtocolOID() + "\n\tSecurityInfos: " + getSecurityInfos() + "\n";
	}

}
