#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

ObjectIdentifier ObjectIdentifierFactory::getObjectIdentifier(std::string oid)
{
	ASN1_OBJECT *asn1Obj;
	asn1Obj = OBJ_txt2obj(oid.c_str(), 1);
	if (!asn1Obj)
	{
		throw CertificationException(CertificationException::UNKNOWN_OID, "ObjectIdentifierFactory::getObjectIdentifier");
	}
	return ObjectIdentifier(asn1Obj);
}

ObjectIdentifier ObjectIdentifierFactory::getObjectIdentifier(int nid)
{
	ASN1_OBJECT *asn1Obj;
	asn1Obj = OBJ_nid2obj(nid);
	if (!asn1Obj)
	{
		throw CertificationException(CertificationException::UNKNOWN_OID, "ObjectIdentifierFactory::getObjectIdentifier");
	}
	return ObjectIdentifier(asn1Obj);
}

ObjectIdentifier ObjectIdentifierFactory::createObjectIdentifier(std::string oid, std::string name)
{
	ASN1_OBJECT *asn1Obj;
	int nid;

	ObjectIdentifierFactory::getObjectIdentifier(oid);

	nid = OBJ_create(oid.c_str(), name.c_str(), name.c_str());
	
	if (nid == NID_undef)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "ObjectIdentifierFactory::createObjectIdentifier");
	}
	asn1Obj = OBJ_nid2obj(nid);
	if (!asn1Obj)
	{
		throw CertificationException(CertificationException::INTERNAL_ERROR, "ObjectIdentifierFactory::createObjectIdentifier");
	}
	return ObjectIdentifier(asn1Obj);
}
