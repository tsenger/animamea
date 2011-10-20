
package de.bund.bsi.jasmin.asn1.bc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

import de.bund.bsi.jasmin.asn1.SecurityInfosInterface;

/**
 *
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 */
public class SecurityInfos implements SecurityInfosInterface{
    
    private DERSequence terminalAuthenticationInfo = null;
    private DERSequence chipAuthenticationInfo = null;
    private DERSequence paceInfo = null;
    private DERSequence paceDomainParameterInfo = null;
    private DERSequence chipAuthenticationDomainParameterInfo = null;
    private DERSequence cardInfoLocator = null;
    
    private byte[] encodedData = null;

    public SecurityInfos()
    {
    }



    /* *
    * Decodes the byte array passed as argument. The decoded values are
    * stored in the member variables of this class that represent the
    * components of the corresponding ASN.1 type.
    *
    * @param encodedData DOCUMENT ME!
    *
    * @ throws ASN1Exception DOCUMENT ME!
    * @ throws IOException DOCUMENT ME!
    */
    public void decode (byte[] encodedData) throws IOException 
    {
    	this.encodedData = encodedData;
    	ASN1Set securityInfos = (ASN1Set) ASN1Object.fromByteArray(encodedData);
    	int anzahlObjekte = securityInfos.size();
    	DERSequence securityInfo[] = new DERSequence[anzahlObjekte];
    	    	
    	for (int i=0;i<anzahlObjekte;i++) {
    		securityInfo[i] = (DERSequence) securityInfos.getObjectAt(i);
    		DERObjectIdentifier oid = (DERObjectIdentifier) securityInfo[i].getObjectAt(0);
    		switch (oid.toString().charAt(18)) {
    		case '2': 
    			terminalAuthenticationInfo = securityInfo[i]; 
    			break;
    		case '3':
    			if (oid.toString().length()==23) chipAuthenticationInfo = securityInfo[i];
    			else chipAuthenticationDomainParameterInfo = securityInfo[i];
    			break;
    		case '4':
    			if (oid.toString().length()==23) paceInfo = securityInfo[i];
    			else paceDomainParameterInfo = securityInfo[i];
    			break;
    		case '6':
    			cardInfoLocator = securityInfo[i];
    			break;    	
    		} //SWITCH
    			
    	} // IF
    	

    }
    
    public byte[] getBytes() 
    {
    	return encodedData;
    }

    public DERSequence getTAI()
    {
        return terminalAuthenticationInfo;
    }

    public DERSequence getCAI()
    {
        return chipAuthenticationInfo;
    }

    @Override
	public PaceInfo getPACEInfo()
    {
        return new PaceInfo(paceInfo);
    }

    public DERSequence getCIL()
    {
        return cardInfoLocator;
    }

    public DERSequence getCADPI()
    {
        return chipAuthenticationDomainParameterInfo;
    }

    public DERSequence getPACEDPI()
    {
        return paceDomainParameterInfo;
    }

    
}
