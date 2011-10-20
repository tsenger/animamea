package de.bund.bsi.jasmin.asn1.bc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERInteger;

import de.bund.bsi.jasmin.asn1.PaceInfoInterface;

public class PaceInfo implements PaceInfoInterface{
	
	private DERObjectIdentifier protocol = null;
	private int version = 0;
	private int parameterId = 0;

	public PaceInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		DERInteger v = (DERInteger)seq.getObjectAt(1);
		version = v.getValue().intValue();
		if (seq.size()>2) {
			DERInteger p = (DERInteger)seq.getObjectAt(2);
			parameterId = p.getValue().intValue();
		}
	}
	
	public PaceInfo(String protocol, int version, int parameterId) throws IOException {
		this.protocol = new DERObjectIdentifier(protocol);
		this.version = version;
		this.parameterId = parameterId;
	}
	
	public String getProtocolString() {
		return protocol.toString();
	}
	
	public byte[] getProtocolBytes() {
		return protocol.getDEREncoded();
	}
	
	public int getVersion() {
		return version;
	}
	
	public int getParameterId() {
		return parameterId;
	}
}
