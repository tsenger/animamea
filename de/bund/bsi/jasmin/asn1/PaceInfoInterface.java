package de.bund.bsi.jasmin.asn1;

/**
*
* @author Tobias Senger (tobias.senger@bsi.bund.de)
*/
public interface PaceInfoInterface {
	
	public String getProtocolString();
	public byte[] getProtocolBytes();
	public int getParameterId();
	public int getVersion();

}
