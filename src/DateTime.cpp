#include <libcryptosec/DateTime.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/NullPointerException.h>

#include <limits>

DateTime::DateTime() :
		seconds(0)
{
}

DateTime::DateTime(const BigInteger& epochTime)
{
	this->seconds = epochTime;
}

DateTime::DateTime(const ASN1_TIME *asn1Time) throw()
{
	THROW_NULL_POINTER_IF(asn1Time == nullptr);
	std::string str(reinterpret_cast<char*>(asn1Time->data), asn1Time->length);
	this->seconds = DateTime::date2epoch(str);
}

DateTime::DateTime(const std::string& asn1Time) throw()
{
	this->seconds = DateTime::date2epoch(asn1Time);
}

DateTime::~DateTime()
{
}

std::string DateTime::toXml(const std::string& tab) const
{	
	ASN1_TIME *gt = this->toAsn1Time();
	std::string str(reinterpret_cast<char*>(gt->data), gt->length);
	str = tab + str; 
	return str;	
}

void DateTime::setSeconds(const BigInteger& epochTime)
{
	this->seconds = epochTime;
}

BigInteger DateTime::getSeconds() const
{
	return this->seconds;
}

time_t DateTime::toTimeT() const throw()
{
	time_t maxTime = std::numeric_limits<time_t>::max();
	THROW_OVERFLOW_IF(this->seconds > maxTime);
	return this->seconds.toInt64();
}

ASN1_TIME* DateTime::toAsn1Time() const
{
	// TODO: porque precisamos dessa lógica?
	// segundos para 01/01/2050 00:00:00 Zulu
	BigInteger asn1TimeLimit("2524608000");
	ASN1_TIME* ret = NULL;

	if(this->seconds < asn1TimeLimit) {
		ret = this->toAsn1UTCTime();
	} else {
		ret = this->toAsn1GeneralizedTime();
	}
	
	return ret;
}

ASN1_TIME* DateTime::toAsn1GeneralizedTime() const
{
	ASN1_TIME *ret;
	DateVal date;
	std::stringstream stream;
	std::string gt;
	
	date = DateTime::getDateVal(this->seconds);
	
	stream.setf(std::ios_base::right);
	stream.fill('0');
	
	stream.width(4); //no maximo 4 digitos para ano
	stream << date.year;
	
	stream.width(2);
	stream << (date.mon + 1);	
	stream.width(2);
	stream << date.dayOfMonth;
	stream.width(2);
	stream << date.hour;
	stream.width(2);
	stream << date.min;
	stream.width(2);
	stream << date.sec;
	stream.width(1);
	stream << "Z";

	gt = stream.str();
	
	ret = ASN1_GENERALIZEDTIME_new();
	
	// TODO: Pode retornar 1 no caso de falha de alocacao de memoria
	ASN1_STRING_set(ret, gt.c_str(), gt.size());

	return ret;
}

ASN1_TIME* DateTime::toAsn1UTCTime() const
{
	ASN1_TIME *ret;
	DateVal date;
	std::stringstream stream;
	std::string tmp;
	std::string utc;
	
	date = DateTime::getDateVal(this->seconds);
	
	stream.setf(std::ios_base::right);
	stream.fill('0');
	
	stream.width(2); // Define um tamanho minimo de 2 chars
	stream << date.year;
	stream >> tmp;
	
	// Pega apenas os dois numeros mais a direita
	if(tmp.size() > 2) {
		tmp = tmp.substr(tmp.size() - 2);
	}
	stream.clear();
	stream.str("");
	
	stream << tmp;
	stream.width(2);
	stream << (date.mon + 1);	
	stream.width(2);
	stream << date.dayOfMonth;
	stream.width(2);
	stream << date.hour;
	stream.width(2);
	stream << date.min;
	stream.width(2);
	stream << date.sec;
	stream.width(1);
	stream << "Z";

	utc = stream.str();
	ret = ASN1_UTCTIME_new();
	
	// TODO: Pode retornar 1 no caso de falha de alocacao de memoria
	ASN1_STRING_set(ret, utc.c_str(), utc.size());

	return ret;
}

std::string DateTime::toISODateTime() const
{
	DateVal date;
	std::stringstream stream;
	
	date = DateTime::getDateVal(this->seconds);
	
	stream.setf(std::ios_base::right);
	stream.fill('0');
	
	stream.width(4); //no maximo 4 digitos para ano
	stream << date.year;
	
	stream.width(1);
	stream << "-"; //delimitador
	
	stream.width(2);
	stream << (date.mon + 1);	

	stream.width(1);
	stream << "-"; //delimitador
	
	stream.width(2);
	stream << date.dayOfMonth;
	
	stream.width(1);
	stream << "T"; //delimitador
	
	stream.width(2);
	stream << date.hour;
	
	stream.width(1);
	stream << ":"; //delimitador
	
	stream.width(2);
	stream << date.min;

	stream.width(1);
	stream << ":"; //delimitador
	
	stream.width(2);
	stream << date.sec;
	
	return stream.str();
}

void DateTime::addSeconds(const BigInteger& seconds)
{
	this->seconds.add(seconds);
}

void DateTime::addMinutes(const BigInteger& minutes)
{
	this->seconds.add(minutes*60);
}

void DateTime::addHours(const BigInteger& hours)
{
	this->seconds.add(hours*60*60);
}

void DateTime::addDays(const BigInteger& days)
{
	this->seconds.add(days*24*60*60);
}

void DateTime::addYears(const BigInteger& years)
{
	this->seconds.add(years*365*24*60*60);
}

bool DateTime::operator ==(const DateTime& other) const
{
	return this->seconds == other.seconds;
}

bool DateTime::operator !=(const DateTime& other) const
{
	return this->seconds != other.seconds;
}

bool DateTime::operator <(const DateTime& other) const
{
	return this->seconds < other.seconds;
}

bool DateTime::operator >(const DateTime& other) const
{
	return this->seconds > other.seconds;
}

bool DateTime::operator >=(const DateTime& other) const
{
	return this->seconds >= other.seconds;
}

bool DateTime::operator <=(const DateTime& other) const
		{
	return this->seconds <= other.seconds;
}
