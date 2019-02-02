#ifndef GENERALNAME_H_
#define GENERALNAME_H_

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/certificate/RDNSequence.h>

#include <openssl/x509v3.h>

#include <string>

class GeneralName
{
public:
	enum Type
	{
		UNDEFINED,
		OTHER_NAME,
		RFC_822_NAME,
		DNS_NAME,
//		X400_ADDRESS,
		DIRECTORY_NAME,
//		EDI_PARTY_NAME
		UNIFORM_RESOURCE_IDENTIFIER,
		IP_ADDRESS,
		REGISTERED_ID,
	};

	GeneralName();
	GeneralName(const GENERAL_NAME *generalName);

	virtual ~GeneralName();

	void setOtherName(const ObjectIdentifier& oid, const std::string& data);
	std::pair<ObjectIdentifier, std::string> getOtherName() const;

	void setRfc822Name(const std::string& data);
	const std::string& getRfc822Name() const;

	void setDnsName(const std::string& data);
	const std::string& getDnsName() const;

	void setUniformResourceIdentifier(const std::string& data);
	const std::string& getUniformResourceIdentifier() const;

	void setIpAddress(const std::string& data);
	const std::string& getIpAddress() const;

	void setDirectoryName(const RDNSequence& data);
	const RDNSequence& getDirectoryName() const;

	void setRegisteredId(const ObjectIdentifier& objectIdentifier);
	const ObjectIdentifier& getRegisteredId() const;

	GeneralName::Type getType() const;

	std::string toXml(const std::string& tab = "") const;

	GENERAL_NAME* getSslObject() const;

	static std::string type2Name(GeneralName::Type type);
	static std::string  data2IpAddress(const unsigned char *data);

protected:
	void clean();

	static unsigned char* ipAddress2Data(const std::string& ipAddress);

	GeneralName::Type type;
	std::string data; /* rfc822Name, dnsName, uniformResourceIdentifier, ipAddress */
	ObjectIdentifier oid; /* otherName */
	
	RDNSequence directoryName;
	ObjectIdentifier registeredId;
};

#endif /*GENERALNAME_H_*/
