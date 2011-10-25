/**
 * 
 */
package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.DERObjectIdentifier;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class BSIObjectIdentifiers {
	
	static final String bsi_de = "0.4.0.127.0.7";
	
	//PACE OIDs

    static final String id_PACE = new String(bsi_de + ".2.2.4");
    
    static final DERObjectIdentifier id_PACE_DH_GM = new DERObjectIdentifier(id_PACE + ".1");
    static final DERObjectIdentifier id_PACE_DH_GM_3DES_CBC_CBC = new DERObjectIdentifier(id_PACE_DH_GM + ".1");
	static final DERObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_128 = new DERObjectIdentifier(id_PACE_DH_GM + ".2");
	static final DERObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_192 = new DERObjectIdentifier(id_PACE_DH_GM + ".3");
	static final DERObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_256 = new DERObjectIdentifier(id_PACE_DH_GM + ".4");
	
	static final DERObjectIdentifier id_PACE_ECDH_GM = new DERObjectIdentifier(id_PACE + ".2");
	static final DERObjectIdentifier id_PACE_ECDH_GM_3DES_CBC_CBC = new DERObjectIdentifier(id_PACE_ECDH_GM + ".1");
	static final DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_128 = new DERObjectIdentifier(id_PACE_ECDH_GM + ".2");
	static final DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_192 = new DERObjectIdentifier(id_PACE_ECDH_GM + ".3");
	static final DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_256 = new DERObjectIdentifier(id_PACE_ECDH_GM + ".4");
	
	static final DERObjectIdentifier id_PACE_DH_IM = new DERObjectIdentifier(id_PACE + ".3");
	static final DERObjectIdentifier id_PACE_DH_IM_3DES_CBC_CBC = new DERObjectIdentifier(id_PACE_DH_IM + ".1");
	static final DERObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_128 = new DERObjectIdentifier(id_PACE_DH_IM + ".2");
	static final DERObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_192 = new DERObjectIdentifier(id_PACE_DH_IM + ".3");
	static final DERObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_256 = new DERObjectIdentifier(id_PACE_DH_IM + ".4");
	
	static final DERObjectIdentifier id_PACE_ECDH_IM = new DERObjectIdentifier(id_PACE + ".4");
	static final DERObjectIdentifier id_PACE_ECDH_IM_3DES_CBC_CBC = new DERObjectIdentifier(id_PACE_ECDH_IM + ".1");
	static final DERObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_128 = new DERObjectIdentifier(id_PACE_ECDH_IM + ".2");
	static final DERObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_192 = new DERObjectIdentifier(id_PACE_ECDH_IM + ".3");
	static final DERObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_256 = new DERObjectIdentifier(id_PACE_ECDH_IM + ".4");
	
	//Chip Authentication OIDs
	
    static final String id_CA = new String(bsi_de + ".2.2.3");
	
	static final DERObjectIdentifier id_CA_DH = new DERObjectIdentifier(id_CA + ".1");
	static final DERObjectIdentifier id_CA_DH_3DES_CBC_CBC = new DERObjectIdentifier(id_CA_DH + ".1");
	static final DERObjectIdentifier id_CA_DH_3DES_CBC_CMAC_128 = new DERObjectIdentifier(id_CA_DH + ".2");
	static final DERObjectIdentifier id_CA_DH_3DES_CBC_CMAC_192 = new DERObjectIdentifier(id_CA_DH + ".3");
	static final DERObjectIdentifier id_CA_DH_3DES_CBC_CMAC_256 = new DERObjectIdentifier(id_CA_DH + ".4");
	
	static final DERObjectIdentifier id_CA_ECDH = new DERObjectIdentifier(id_CA + ".2");
	static final DERObjectIdentifier id_CA_ECDH_3DES_CBC_CBC = new DERObjectIdentifier(id_CA_ECDH + ".1");
	static final DERObjectIdentifier id_CA_ECDH_3DES_CBC_CMAC_128 = new DERObjectIdentifier(id_CA_ECDH + ".2");
	static final DERObjectIdentifier id_CA_ECDH_3DES_CBC_CMAC_192 = new DERObjectIdentifier(id_CA_ECDH + ".3");
	static final DERObjectIdentifier id_CA_ECDH_3DES_CBC_CMAC_256 = new DERObjectIdentifier(id_CA_ECDH + ".4");
	
	//Chip Authentication Public Key OIDs
	
	static final String id_PK = new String(bsi_de + ".2.2.1");
	static final DERObjectIdentifier id_PK_DH = new DERObjectIdentifier(id_PK + ".1");
	static final DERObjectIdentifier id_PK_ECDH = new DERObjectIdentifier(id_PK + ".2");
	
	//Terminal Authentication OIDs
	
	static final String id_TA = new String(bsi_de + ".2.2.2");
	
	static final DERObjectIdentifier id_TA_RSA = 				new DERObjectIdentifier(id_TA + ".1");
	static final DERObjectIdentifier id_TA_RSA_v1_5_SHA_1 = 	new DERObjectIdentifier(id_TA_RSA + ".1");
	static final DERObjectIdentifier id_TA_RSA_v1_5_SHA_256 = 	new DERObjectIdentifier(id_TA_RSA + ".2");
	static final DERObjectIdentifier id_TA_RSA_PSS_SHA_1 = 		new DERObjectIdentifier(id_TA_RSA + ".3");
	static final DERObjectIdentifier id_TA_RSA_PSS_SHA_256 = 	new DERObjectIdentifier(id_TA_RSA + ".4");
	static final DERObjectIdentifier id_TA_RSA_v1_5_SHA_512 = 	new DERObjectIdentifier(id_TA_RSA + ".5");
	static final DERObjectIdentifier id_TA_RSA_PSS_SHA_512 = 	new DERObjectIdentifier(id_TA_RSA + ".6");
	
	static final DERObjectIdentifier id_TA_ECDSA = 				new DERObjectIdentifier(id_TA + ".2");
	static final DERObjectIdentifier id_TA_ECDSA_SHA_1 = 		new DERObjectIdentifier(id_TA_ECDSA + ".1");
	static final DERObjectIdentifier id_TA_ECDSA_SHA_224 = 		new DERObjectIdentifier(id_TA_ECDSA + ".2");
	static final DERObjectIdentifier id_TA_ECDSA_SHA_256 = 		new DERObjectIdentifier(id_TA_ECDSA + ".3");
	static final DERObjectIdentifier id_TA_ECDSA_SHA_384 = 		new DERObjectIdentifier(id_TA_ECDSA + ".4");
	static final DERObjectIdentifier id_TA_ECDSA_SHA_512 = 		new DERObjectIdentifier(id_TA_ECDSA + ".5");
	
	//Restricted Identification OIDs
	
	static final String id_RI = new String(bsi_de + ".2.2.5");
	
	static final DERObjectIdentifier id_RI_DH = new DERObjectIdentifier(id_RI + ".1");
	static final DERObjectIdentifier id_RI_DH_SHA_1 = 		new DERObjectIdentifier(id_RI_DH + ".1");
	static final DERObjectIdentifier id_RI_DH_SHA_224 = 	new DERObjectIdentifier(id_RI_DH + ".2");
	static final DERObjectIdentifier id_RI_DH_SHA_256 = 	new DERObjectIdentifier(id_RI_DH + ".3");
	static final DERObjectIdentifier id_RI_DH_SHA_384 = 	new DERObjectIdentifier(id_RI_DH + ".4");
	static final DERObjectIdentifier id_RI_DH_SHA_512 = 	new DERObjectIdentifier(id_RI_DH + ".5");
	
	static final DERObjectIdentifier id_RI_ECDH = new DERObjectIdentifier(id_RI + ".2");
	static final DERObjectIdentifier id_RI_ECDH_SHA_1 = 	new DERObjectIdentifier(id_RI_ECDH + ".1");
	static final DERObjectIdentifier id_RI_ECDH_SHA_224 = 	new DERObjectIdentifier(id_RI_ECDH + ".2");
	static final DERObjectIdentifier id_RI_ECDH_SHA_256 = 	new DERObjectIdentifier(id_RI_ECDH + ".3");
	static final DERObjectIdentifier id_RI_ECDH_SHA_384 = 	new DERObjectIdentifier(id_RI_ECDH + ".4");
	static final DERObjectIdentifier id_RI_ECDH_SHA_512 = 	new DERObjectIdentifier(id_RI_ECDH + ".5");
	
	//CardInfoLocator OID
	
	static final DERObjectIdentifier id_CI = new DERObjectIdentifier(bsi_de + ".2.2.6");
	
	//eIDSecurityInfo
	
	static final DERObjectIdentifier id_eIDSecurity = new DERObjectIdentifier(bsi_de + ".2.2.7");
	
	//PrivilegedTerminalInfo
	
	static final DERObjectIdentifier id_PT = new DERObjectIdentifier(bsi_de + ".2.2.8");
	
	//Roles
	
	static final DERObjectIdentifier id_roles = new DERObjectIdentifier(bsi_de + ".3.1.2");
	
	static final DERObjectIdentifier id_IS = new DERObjectIdentifier(id_roles + ".1");
	static final DERObjectIdentifier id_AT = new DERObjectIdentifier(id_roles + ".2");
	static final DERObjectIdentifier id_ST = new DERObjectIdentifier(id_roles + ".3");
	
	
	

}
