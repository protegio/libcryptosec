#include <libcryptosec/certificate/RDNSequence.h>

#include <openssl/x509.h>

#include <string>
#include <iostream>
#include <vector>
#include <map>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <libcryptosec/exception/CertificationException.h>

RDNSequence::RDNSequence()
{
}

RDNSequence::RDNSequence(const RDNSequence& rdn) :
		newEntries(rdn.getEntries())
{
}

RDNSequence::RDNSequence(const X509_NAME *rdn)
{
	if (rdn == NULL) {
		throw CertificationException("" /* TODO */ );
	}

	int num = X509_NAME_entry_count(rdn);
	for (int i = 0; i < num; i++) {
		std::pair<ObjectIdentifier, std::string> oneEntry;

		X509_NAME_ENTRY *nameEntry = X509_NAME_get_entry(rdn, i);
		if (nameEntry == NULL) {
			throw CertificationException("" /* TODO */ );
		}

		const ASN1_OBJECT *oid = X509_NAME_ENTRY_get_object(nameEntry);
		if (oid == NULL) {
			throw CertificationException("" /* TODO */ );
		}

		const char* data = (const char*) X509_NAME_ENTRY_get_data(nameEntry)->data;
		if (data == NULL) {
			throw CertificationException("" /* TODO */ );
		}

		oneEntry.first = ObjectIdentifier(oid);
		oneEntry.second = std::string(data);
		this->newEntries.push_back(oneEntry);
	}
}

RDNSequence::RDNSequence(const STACK_OF(X509_NAME_ENTRY) *entries)
{
	if (entries == NULL) {
		throw CertificationException("" /* TODO */ );
	}

	int num = sk_X509_NAME_ENTRY_num(entries);
	for (int i = 0; i < num; i++) {
		std::pair<ObjectIdentifier, std::string> oneEntry;

		X509_NAME_ENTRY *nameEntry = sk_X509_NAME_ENTRY_value(entries, i);
		if (nameEntry == NULL) {
			throw CertificationException("" /* TODO */ );
		}

		const ASN1_OBJECT *oid = X509_NAME_ENTRY_get_object(nameEntry);
		if (oid == NULL) {
			throw CertificationException("" /* TODO */ );
		}

		const char *data = (const char *) X509_NAME_ENTRY_get_data(nameEntry)->data;
		if (data == NULL) {
			throw CertificationException("" /* TODO */ );
		}

		oneEntry.first = ObjectIdentifier(oid);
		oneEntry.second = std::string(data);
		this->newEntries.push_back(oneEntry);
	}
}

RDNSequence::~RDNSequence()
{
}

RDNSequence& RDNSequence::operator=(const RDNSequence& value)
{
	if(&value == this) {
		return *this;
	}
	this->newEntries = value.newEntries;
	return *this;
}


RDNSequence& RDNSequence::operator=(RDNSequence&& value) {
	if(&value == this) {
		return *this;
	}
	this->newEntries = std::move(value.newEntries);
	return *this;
}

std::string RDNSequence::getXmlEncoded(const std::string& tab) const
{
	std::vector<std::pair<ObjectIdentifier, std::string> >::iterator iterEntries;
	std::string ret;
	int nid = 0;
	
	ret = tab + "<RDNSequence>\n";
	for (auto entry : this->newEntries) {
		nid = iterEntries->first.getNid();
		if (RDNSequence::id2Type(nid) != RDNSequence::UNKNOWN) {
			ret += tab + "\t<" + RDNSequence::getNameId(RDNSequence::id2Type(nid)) + ">" + iterEntries->second + "</" + RDNSequence::getNameId(RDNSequence::id2Type(nid)) + ">\n";
		} else {
			ret += tab + "\t<unknownAttribute>" + iterEntries->first.getOid() + ":" + iterEntries->second + "</unknownAttribute>\n";
		}
	}
	ret += tab + "</RDNSequence>\n";
	return ret;
}

void RDNSequence::addEntry(RDNSequence::EntryType type, const std::string& value)
{
	std::pair<ObjectIdentifier, std::string> oneEntry;
	if (type != RDNSequence::UNKNOWN)
	{
		oneEntry.first = ObjectIdentifierFactory::getObjectIdentifier(RDNSequence::type2Id(type));
		oneEntry.second = value;
		this->newEntries.push_back(oneEntry);
	}
}

void RDNSequence::addEntry(RDNSequence::EntryType type, const std::vector<std::string>& values)
{
	for (auto entry : values) {
		this->addEntry(type, entry);
	}
}

std::vector<std::string> RDNSequence::getEntries(RDNSequence::EntryType type) const
{
	std::vector<std::string> ret;
	for (auto entry : this->newEntries) {
		if (id2Type(entry.first.getNid()) == type) {
			ret.push_back(entry.second);
		}
	}
	return ret;
}

std::vector<std::pair<ObjectIdentifier, std::string> > RDNSequence::getUnknownEntries() const
{
	std::vector<std::pair<ObjectIdentifier, std::string> > ret;
	for (auto entry : this->newEntries) {
		if (id2Type(entry.first.getNid()) == RDNSequence::UNKNOWN) {
			std::pair<ObjectIdentifier, std::string> oneEntry;
			oneEntry.first = entry.first;
			oneEntry.second = entry.second;
			ret.push_back(oneEntry);
		}
	}
	return ret;
}

const std::vector<std::pair<ObjectIdentifier, std::string> >& RDNSequence::getEntries() const
{
	return this->newEntries;
}

X509_NAME* RDNSequence::getX509Name() const
{
	X509_NAME *ret = X509_NAME_new();
	int rc = 0;

	for (auto iterEntries : this->newEntries) {
		X509_NAME_ENTRY *entry = X509_NAME_ENTRY_new();
		if (entry == NULL) {
			throw CertificationException("" /* TODO */);
		}

		rc = X509_NAME_ENTRY_set_object(entry, iterEntries.first.getObjectIdentifier());
		if (rc == 0) {
			throw CertificationException("" /* TODO */);
		}

		rc = X509_NAME_ENTRY_set_data(entry, MBSTRING_ASC, (unsigned char *) iterEntries.second.c_str(), iterEntries.second.length());
		if (rc == 0) {
			throw CertificationException("" /* TODO */);
		}

		rc = X509_NAME_add_entry(ret, entry, -1, 0);
		if (rc == 0) {
			throw CertificationException("" /* TODO */);
		}

		X509_NAME_ENTRY_free(entry);
	}
	return ret;
}

std::string RDNSequence::getNameId(RDNSequence::EntryType type)
{
	std::string ret;
	switch (type)
	{
		case RDNSequence::COUNTRY:
			ret = "countryName";
			break;
		case RDNSequence::ORGANIZATION:
			ret = "organizationName";
			break;
		case RDNSequence::ORGANIZATION_UNIT:
			ret = "organizationalUnitName";
			break;
		case RDNSequence::DN_QUALIFIER:
			ret = "dnQualifier";
			break;
		case RDNSequence::STATE_OR_PROVINCE:
			ret = "stateOrProvinceName";
			break;
		case RDNSequence::COMMON_NAME:
			ret = "commonName";
			break;
		case RDNSequence::SERIAL_NUMBER:
			ret = "serialNumber";
			break;
		case RDNSequence::LOCALITY:
			ret = "localityName";
			break;
		case RDNSequence::TITLE:
			ret = "title";
			break;
		case RDNSequence::SURNAME:
			ret = "surname";
			break;
		case RDNSequence::GIVEN_NAME:
			ret = "givenName";
			break;
		case RDNSequence::INITIALS:
			ret = "initials";
			break;
		case RDNSequence::PSEUDONYM:
			ret = "pseudonym";
			break;
		case RDNSequence::GENERATION_QUALIFIER:
			ret = "generationQualifier";
			break;
		case RDNSequence::EMAIL:
			ret = "e-mail";
			break;
		case RDNSequence::DOMAIN_COMPONENT:
			ret = "domainComponent";
			break;
		default:
			ret = "unsupported";
			break;
	}
	return ret;
}

RDNSequence::EntryType RDNSequence::id2Type(int id)
{
	RDNSequence::EntryType ret;
	switch (id)
	{
		case NID_countryName:
			ret = RDNSequence::COUNTRY;
			break;
		case NID_organizationName:
			ret = RDNSequence::ORGANIZATION;
			break;
		case NID_organizationalUnitName:
			ret = RDNSequence::ORGANIZATION_UNIT;
			break;
		case NID_dnQualifier:
			ret = RDNSequence::DN_QUALIFIER;
			break;
		case NID_stateOrProvinceName:
			ret = RDNSequence::STATE_OR_PROVINCE;
			break;
		case NID_commonName:
			ret = RDNSequence::COMMON_NAME;
			break;
		case NID_serialNumber:
			ret = RDNSequence::SERIAL_NUMBER;
			break;
		case NID_localityName:
			ret = RDNSequence::LOCALITY;
			break;
		case NID_title:
			ret = RDNSequence::TITLE;
			break;
		case NID_surname:
			ret = RDNSequence::SURNAME;
			break;
		case NID_givenName:
			ret = RDNSequence::GIVEN_NAME;
			break;
		case NID_initials:
			ret = RDNSequence::INITIALS;
			break;
		case NID_pseudonym:
			ret = RDNSequence::PSEUDONYM;
			break;
		case NID_generationQualifier:
			ret = RDNSequence::GENERATION_QUALIFIER;
			break;
		case NID_pkcs9_emailAddress:
			ret = RDNSequence::EMAIL;
			break;
		case NID_domainComponent:
			ret = RDNSequence::DOMAIN_COMPONENT;
			break;
		default:
			ret = RDNSequence::UNKNOWN;
	}
	return ret;
}

int RDNSequence::type2Id(RDNSequence::EntryType type)
{
	int ret;
	switch (type)
	{
		case RDNSequence::COUNTRY:
			ret = NID_countryName;
			break;
		case RDNSequence::ORGANIZATION:
			ret = NID_organizationName;
			break;
		case RDNSequence::ORGANIZATION_UNIT:
			ret = NID_organizationalUnitName;
			break;
		case RDNSequence::DN_QUALIFIER:
			ret = NID_dnQualifier;
			break;
		case RDNSequence::STATE_OR_PROVINCE:
			ret = NID_stateOrProvinceName;
			break;
		case RDNSequence::COMMON_NAME:
			ret = NID_commonName;
			break;
		case RDNSequence::SERIAL_NUMBER:
			ret = NID_serialNumber;
			break;
		case RDNSequence::LOCALITY:
			ret = NID_localityName;
			break;
		case RDNSequence::TITLE:
			ret = NID_title;
			break;
		case RDNSequence::SURNAME:
			ret = NID_surname;
			break;
		case RDNSequence::GIVEN_NAME:
			ret = NID_givenName;
			break;
		case RDNSequence::INITIALS:
			ret = NID_initials;
			break;
		case RDNSequence::PSEUDONYM:
			ret = NID_pseudonym;
			break;
		case RDNSequence::GENERATION_QUALIFIER:
			ret = NID_generationQualifier;
			break;
		case RDNSequence::EMAIL:
			ret = NID_pkcs9_emailAddress;
			break;
		case RDNSequence::DOMAIN_COMPONENT:
			ret = NID_domainComponent;
			break;
		case RDNSequence::UNKNOWN:
			ret = NID_undef;
			break;
	}
	return ret;
}
