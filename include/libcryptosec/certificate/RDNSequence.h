#ifndef RDNSEQUENCE_H_
#define RDNSEQUENCE_H_

#include <libcryptosec/certificate/ObjectIdentifier.h>

#include <openssl/x509.h>

#include <string>
#include <vector>

class RDNSequence
{
public:
	enum EntryType
	{
		COUNTRY = 0,
		STATE_OR_PROVINCE = 1,
		LOCALITY = 2,
		ORGANIZATION = 3,
		ORGANIZATION_UNIT = 4,
		COMMON_NAME = 5,
		EMAIL = 6,
		DN_QUALIFIER = 7,
		SERIAL_NUMBER = 8,
		TITLE = 9,
		SURNAME = 10,
		GIVEN_NAME = 11,
		INITIALS = 12,
		PSEUDONYM = 13,
		GENERATION_QUALIFIER = 14,
		DOMAIN_COMPONENT = 15,
		UNKNOWN = 16,
	};
	
	RDNSequence();
	RDNSequence(const X509_NAME *rdn);
	RDNSequence(const STACK_OF(X509_NAME_ENTRY) *entries);
	RDNSequence(const RDNSequence& rdn);
	RDNSequence(RDNSequence&& rdn);

	virtual ~RDNSequence();

	RDNSequence& operator=(const RDNSequence& value);
	RDNSequence& operator=(RDNSequence&& value);

	std::string getXmlEncoded(const std::string& tab = "") const;
	void addEntry(RDNSequence::EntryType type, const std::string& value);
	void addEntry(RDNSequence::EntryType type, const std::vector<std::string>& values);
	std::vector<std::string> getEntries(RDNSequence::EntryType type) const;
	std::vector<std::pair<ObjectIdentifier, std::string> > getUnknownEntries() const;
	const std::vector<std::pair<ObjectIdentifier, std::string> >& getEntries() const;
	X509_NAME* getX509Name() const;

protected:
	static RDNSequence::EntryType id2Type(int id);
	static int type2Id(RDNSequence::EntryType type);
	static std::string getNameId(RDNSequence::EntryType type);

	std::vector<std::pair<ObjectIdentifier, std::string> > newEntries;
};

#endif /*RDNSEQUENCE_H_*/
