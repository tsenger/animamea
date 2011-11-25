package de.tsenger.animamea.asn1;

/**
*
* @author Tobias Senger (tobias@t-senger.de)
*/
public interface PaceInfoInterface {
	
	public String getProtocolOID();
	public int getVersion();
	/**
	 * @return Returns -1 if the optional field parameterID is not used.
	 */
	public int getParameterId();

}
