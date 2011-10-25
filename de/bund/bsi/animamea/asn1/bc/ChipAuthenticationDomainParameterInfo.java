/**
 * 
 */
package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import de.bund.bsi.animamea.asn1.ChipAuthenticationDomainParameterInfoInterface;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class ChipAuthenticationDomainParameterInfo implements ChipAuthenticationDomainParameterInfoInterface{

	private DERObjectIdentifier protocol = null;
	private AlgorithmIdentifier domainParameter = null;
	private DERInteger keyId = null;
	
	/**
	 * @param derSequence
	 */
	public ChipAuthenticationDomainParameterInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		domainParameter = (AlgorithmIdentifier)seq.getObjectAt(1);
		
		if (seq.size()>2) {
			keyId = (DERInteger)seq.getObjectAt(2);
		}
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.ChipAuthenticationDomainParameterInfoInterface#getProtocolString()
	 */
	@Override
	public String getProtocolString() {
		return protocol.toString();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.ChipAuthenticationDomainParameterInfoInterface#getProtocolBytes()
	 */
	@Override
	public byte[] getProtocolBytes() {
		return protocol.getDEREncoded();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.ChipAuthenticationDomainParameterInfoInterface#getDomainParameter()
	 */
	@Override
	public byte[] getDomainParameter() {
		return domainParameter.getDEREncoded();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.ChipAuthenticationDomainParameterInfoInterface#getKeyId()
	 */
	@Override
	public int getKeyId() {
		if (keyId==null) return 0;
		else return keyId.getValue().intValue();
	}

}
