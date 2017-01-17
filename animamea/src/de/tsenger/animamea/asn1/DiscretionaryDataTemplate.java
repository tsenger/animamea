package de.tsenger.animamea.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.eac.BidirectionalMap;

public class DiscretionaryDataTemplate extends ASN1Object {

	private ASN1ObjectIdentifier oid;
	private byte[] dataContent;
	
	static BidirectionalMap ExtensionType = new BidirectionalMap();
    static
    {
    	ExtensionType.put(BSIObjectIdentifiers.id_AT_eIDAccess, "id_AT eID Access");
    	ExtensionType.put(BSIObjectIdentifiers.id_AT_specialFunctions, "id_AT Special Functions");
    	ExtensionType.put(BSIObjectIdentifiers.id_AT_eID_Biometrics, "id_AT eID Biometrics");
    	ExtensionType.put(BSIObjectIdentifiers.description, "Hash of Certificate Description");
    	ExtensionType.put(BSIObjectIdentifiers.sector, "Terminal Sector for id_RI");
    	ExtensionType.put(BSIObjectIdentifiers.PS_sector, "Terminal Sector for Pseudonymous Signatures");
    }

	public DiscretionaryDataTemplate(ASN1ObjectIdentifier oid, byte[] data) {
		this.oid = oid;
		this.dataContent = data;

	}

	private DiscretionaryDataTemplate(DERApplicationSpecific appSpe) throws IOException {
		setDiscretionaryData(appSpe);
	}

	private void setDiscretionaryData(DERApplicationSpecific appSpe) throws IOException {
		if (appSpe.getApplicationTag() == EACTags.DISCRETIONARY_DATA_TEMPLATE) {

			ASN1InputStream content = new ASN1InputStream(appSpe.getContents());
			ASN1Primitive tmpObj;

			while ((tmpObj = content.readObject()) != null) {

				if (tmpObj instanceof ASN1ObjectIdentifier)
					oid = ASN1ObjectIdentifier.getInstance(tmpObj);

				else if (tmpObj instanceof DERApplicationSpecific) {
					DERApplicationSpecific aSpe = (DERApplicationSpecific) tmpObj;
					if (aSpe.getApplicationTag() == EACTags.DISCRETIONARY_DATA) {
						dataContent = aSpe.getContents();
					} else {
						content.close();
						throw new IOException("Invalid Object, no discretionaray data");
					}
				}
				else if (tmpObj instanceof DERTaggedObject) {
					DERTaggedObject aSpe = (DERTaggedObject) tmpObj;
					//Tag 0x80 and 0x81 are valid tags here
					if (aSpe.getTagNo() == 0x00 || aSpe.getTagNo() == 0x01) {
						dataContent = ((DEROctetString) aSpe.getObject()).getOctets();
					} else {
						content.close();
						throw new IOException("Invalid Object, no valid data");
					}
				}
			}
			content.close();
		} else
			throw new IOException("not a DISCRETIONARY DATA TEMPLATE :" + appSpe.getApplicationTag());
	}

	public byte[] getDataContent() {
		return dataContent;
	}
	
	public ASN1ObjectIdentifier getOid() {
		return oid;
	}
	
	public String getExtensionDescription() {
		String extDescriptionString = (String)ExtensionType.get(this.oid);
		if(extDescriptionString==null) extDescriptionString = "unknown Extension (OID: "+this.oid.toString()+")";
    	return extDescriptionString;
    }

	public static DiscretionaryDataTemplate getInstance(Object obj) throws IOException {
		if (obj instanceof DiscretionaryDataTemplate) {
			return (DiscretionaryDataTemplate) obj;
		} else if (obj != null) {
			return new DiscretionaryDataTemplate(DERApplicationSpecific.getInstance(obj));
		}

		return null;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(oid);
		v.add(new DERApplicationSpecific(EACTags.DISCRETIONARY_DATA, dataContent));
		try {
			return new DERApplicationSpecific(false, EACTags.DISCRETIONARY_DATA_TEMPLATE, new DERSequence(v));
		} catch (IOException e) {
			throw new IllegalStateException("unable to convert Discretionary Data Template");
		}
	}

}
