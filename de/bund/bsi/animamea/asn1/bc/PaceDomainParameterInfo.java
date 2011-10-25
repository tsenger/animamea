/**
 * 
 */
package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import de.bund.bsi.animamea.asn1.PaceDomainParameterInfoInterface;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class PaceDomainParameterInfo implements PaceDomainParameterInfoInterface{

	private DERObjectIdentifier protocol = null;
	private AlgorithmIdentifier domainParameter = null;
	private DERInteger parameterId = null;
	
	public PaceDomainParameterInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		domainParameter = (AlgorithmIdentifier)seq.getObjectAt(1);
		
		if (seq.size()>2) {
			parameterId = (DERInteger)seq.getObjectAt(2);
		}
	}
	
	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.PaceDomainParameterInfoInterface#getProtocolString()
	 */
	@Override
	public String getProtocolString() {
		return protocol.toString();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.PaceDomainParameterInfoInterface#getProtocolBytes()
	 */
	@Override
	public byte[] getProtocolBytes() {
		return protocol.getDEREncoded();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.PaceDomainParameterInfoInterface#getDomainParameter()
	 */
	@Override
	public byte[] getDomainParameter() {
		return domainParameter.getDEREncoded();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.PaceDomainParameterInfoInterface#getParameterId()
	 */
	@Override
	public int getParameterId() {
		if (parameterId==null) return 0;
		else return parameterId.getValue().intValue();
	}

}
