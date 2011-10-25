package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

import de.bund.bsi.animamea.asn1.PaceInfoInterface;

/**
*
* @author Tobias Senger (tobias.senger@bsi.bund.de)
*/
public class PaceInfo implements PaceInfoInterface{
	
	private DERObjectIdentifier protocol = null;
	private DERInteger version = null;
	private DERInteger parameterId = null;

	public PaceInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		version = (DERInteger)seq.getObjectAt(1);
		
		if (seq.size()>2) {
			parameterId = (DERInteger)seq.getObjectAt(2);
		}
	}
	
	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.PaceInfoInterface#getProtocolString()
	 */
	@Override
	public String getProtocolString() {
		return protocol.toString();
	}
	
	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.PaceInfoInterface#getProtocolBytes()
	 */
	@Override
	public byte[] getProtocolBytes() {
		return protocol.getDEREncoded();
	}
	
	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.PaceInfoInterface#getVersion()
	 */
	@Override
	public int getVersion() {
		return version.getValue().intValue();
	}
	
	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.PaceInfoInterface#getParameterId()
	 */
	@Override
	public int getParameterId() {
		if (parameterId==null) return 0;
		else return parameterId.getValue().intValue();
	}
}
