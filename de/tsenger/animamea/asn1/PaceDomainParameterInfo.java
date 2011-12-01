/**
 * 
 */
package de.tsenger.animamea.asn1;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class PaceDomainParameterInfo {

	private DERObjectIdentifier protocol = null;
	private AlgorithmIdentifier domainParameter = null;
	private DERInteger parameterId = null;
	
	public PaceDomainParameterInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		domainParameter = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
		
		if (seq.size()>2) {
			parameterId = (DERInteger)seq.getObjectAt(2);
		}
	}
	
	public String getProtocolOID() {
		return protocol.toString();
	}

	
	public AlgorithmIdentifier getDomainParameter() {
		return domainParameter;
	}

	
	public int getParameterId() {
		if (parameterId==null) return -1; // optionales Feld parameterId nicht vorhanden
		else return parameterId.getValue().intValue();
	}
	
	@Override
	public String toString() {
		return "PaceDomainParameterInfo\n\tOID: " + getProtocolOID() + "\n\tDomainParameter: \n\t\t" + getDomainParameter().getAlgorithm() + "\n\t\t" + getDomainParameter().getParameters() + "\n\tParameterId: " + getParameterId() + "\n";
	}
}
