#ifndef USERNOTICE_H_
#define USERNOTICE_H_

#include <openssl/x509v3.h>

#include <string>
#include <vector>

class UserNotice
{
public:
	UserNotice();
	UserNotice(const USERNOTICE *userNotice);
	UserNotice(const std::string& organization, const std::vector<long>& noticeNumbers, const std::string& explicitText);

	virtual ~UserNotice();

	void setOrganization(const std::string& organization);
	const std::string& getOrganization() const;

	void setNoticeNumbers(const std::vector<long>& noticeNumbers);
	const std::vector<long>& getNoticeNumbers() const;

	void setExplicitText(const std::string& explicitText);
	const std::string& getExplicitText() const;

	void setNoticeReference(const std::string& organization, const std::vector<long>& noticeNumbers);
	std::pair<std::string, std::vector<long> > getNoticeReference() const;

	USERNOTICE* getSslObject() const;

	std::string toXml(const std::string& tab = "") const;

protected:
	std::string organization;
	std::vector<long> noticeNumbers;
	std::string explicitText;
};

#endif /*USERNOTICE_H_*/
