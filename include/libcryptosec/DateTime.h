#ifndef DATETIME_H_
#define DATETIME_H_

#include <libcryptosec/BigInteger.h>
#include <libcryptosec/Macros.h>

#include <openssl/asn1.h>

#include <time.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>


/**
 * @ingroup Util
 */

/**
 * @brief Implementa a representação da data e hora.
 */
class DateTime
{
public:
	
	/**
	 * @struct DateVal
	 * Contém dados sobre uma data e hora. Equivalente ao struct tm (time.h)
	 */
	struct DateVal
	{
		  uint32_t sec;			/* Seconds.	[0-60] (1 leap second) */
		  uint32_t min;			/* Minutes.	[0-59] */
		  uint32_t hour;		/* Hours.	[0-23] */
		  uint32_t dayOfMonth;	/* Day.		[1-31] */
		  uint32_t mon;			/* Month.	[0-11] */
		  uint32_t year;		/* Year.	[0-UINT32_MAX] */
		  uint32_t dayOfWeek;	/* Day of week.	[0-6] */
		  uint32_t dayOfYear;	/* Days of year.[0-365]	*/
	};
	
	/**
	 * Construtor padrão.
	 *
	 * Cria um objeto DateTime com data 0 (00:00:00 UTC, 1 de Janeiro de 1970).
	 */
	DateTime();
	
	/**
	 * @brief Cria um objeto DateTime baseado na representação epoch.
	 *
	 * @param dateTime data no formato epoch em um estrutura time_t.
	 */
	//DateTime(time_t dateTime);
	
	/**
	 * @brief Cria um objeto DateTime baseado na representação epoch.
	 *
	 * @param dateTime data no formato epoch em um BigInteger.
	 */
	DateTime(const BigInteger& dateTime);

	/**
	 * @brief Cria um objeto DateTime baseado na representação ASN1_TIME.
	 *
	 * @param asn1Time data no formato ASN1_TIME.
	 *
	 * @throw out_of_range se asn1Time não representa uma data válida.
	 */	
	DateTime(const ASN1_TIME *asn1Time) throw();

	/**
	 * @brief Cria um objeto DateTime baseado na representação UTCTime ou GeneralizedTime.
	 *
	 * Usar o formato YYMMDDThhmmssZ para UTCTime.
	 *
	 * Usar o formato YYYYMMDDThhmmssZ para GeneralizedTime.
	 *
	 * @param utc string no formato UTCTime ou GeneralizedTime.
	 *
	 * @throw out_of_range se asn1Time não representa uma data válida.
	 */	
	DateTime(const std::string& asn1Time) throw();

	/**
	 * Destrutor padrão.
	 */
	virtual ~DateTime();
	
	/** 
	 * @brief Obtem representação da data em formato XML.
	 *
	 * @param tab Tabulação base para ser usada na representação XML.
	 *
	 * @return data em formato XML.
	 */	
	std::string toXml(const std::string& tab = "") const;

	/**
	 * @brief Atribui a data no formato epoch.
	 *
	 * @param epochTime data desejada no formato epoch.
	 */
	void setSeconds(const BigInteger& epochTime);

	/**
	 * @brief Retorna a data no formato epoch.
	 * @return data no formato epoch.
	 */
	BigInteger getSeconds() const;

	/**
	 * @brief Retorna a data no formato epoch em uma estrutura timet_t.
	 * @return data no formato epoch em uma estrutura time_t.
	 * @throw overflow_error if the number of seconds overflows the time_t type.
	 */
	time_t toTimeT() const throw();

	/**
	 * Obtem data em formato ASN1.
	 * @return objeto ASN1_TIME no formato UTCTime se ano inferior a 2050, GeneralizedTime caso contrário.
	 */
	ASN1_TIME* toAsn1Time() const;

	/**
	* Obtem data em formato ASN1.
	* @return objeto ASN1_TIME no formato GeneralizedTime (YYYYMMDDHHMMSSZ).
	*/
	ASN1_TIME* toAsn1GeneralizedTime() const;

	/**
	* Obtem data em formato ASN1.
	* @return objeto ASN1_TIME no formato UTCTime (YYMMDDHHMMSSZ).
	*/
	ASN1_TIME* toAsn1UTCTime() const;

	/**
	 * Obtem data em formato ISO8601.
	 * @return string no formato YYYY-MM-DDTHH:MM:SS (no GMT).
	 */
	std::string toISODateTime() const;

	/**
	 * Adiciona segundos.
	 * @param seconds quantidade de segundos.
	 * */	
	void addSeconds(const BigInteger& seconds);
	
	/**
	 * Adiciona minutos.
	 * @param minutes quantidade de minutos.
	 * */
	void addMinutes(const BigInteger& minutes);
	
	/**
	 * Adiciona horas.
	 * @param hours quantidade de horas.
	 * */	
	void addHours(const BigInteger& hours);
	
	/**
	 * @brief Adiciona dias.
	 * @param days quantidade de dias.
	 * */	
	void addDays(const BigInteger& days);

	/**
	 * @brief Adiciona anos.
	 * @param years quantidade de anos.
	 * */	
	void addYears(const BigInteger& years);
	
	/**
	 * Comparison operators.
	 */
	bool operator ==(const DateTime& other) const;
	bool operator !=(const DateTime& other) const;
	bool operator <(const DateTime& other) const;
	bool operator >(const DateTime& other) const;
	bool operator >=(const DateTime& other) const;
	bool operator <=(const DateTime& other) const;

	/**
	 * @brief Transforma do formato em segundos (epoch) para ano, mês, dia, hora, minuto e segundo.
	 * @param epoch data e hora no formato epoch.
	 * @return Estrutura com ano, mês, dia, hora, minuto e segundo.
	 * */
	static DateTime::DateVal getDateVal(const BigInteger& epoch)
	{
		const uint64_t SECS_DAY = 86400L;
		DateTime::DateVal ret;
		BigInteger yearsSinceEpoch(0L);
		BigInteger leapDays(0L);
		BigInteger daysSinceEpoch(0L);
		BigInteger tmp;
		BigInteger hours(epoch);
		BigInteger days(epoch);
		uint32_t dayOfYear;
		uint32_t sizeOfMonth;

		hours.mod(SECS_DAY);
		days.div(SECS_DAY);

		tmp = hours % 60;
		ret.sec = tmp.toInt32();

		tmp = (hours % 3600).div(60);
		ret.min = tmp.toInt32();

		hours.div(3600);
		ret.hour = hours.toInt32();

		ret.year = 1970;

		while(days >= DateTime::getYearSize(ret.year)) {
			days.sub(DateTime::getYearSize(ret.year));
			ret.year++;
		}

		ret.dayOfYear = days.toInt32();
		dayOfYear = ret.dayOfYear;

		ret.mon = 0;
		sizeOfMonth = DateTime::getMonthSize(ret.mon, ret.year);
		while(dayOfYear >= sizeOfMonth) {
			dayOfYear-= sizeOfMonth;
			ret.mon++;
			sizeOfMonth = DateTime::getMonthSize(ret.mon, ret.year);
		}
		ret.dayOfMonth = dayOfYear + 1;

		ret.dayOfWeek = DateTime::getDayOfWeek(ret.year, ret.mon, ret.dayOfMonth);

		return ret;
	}

	/**
	 * @brief Transforma uma data no formato UTCTime ou GeneralizedTime para epoch.
	 *
	 * - UTCTime: 'YYMMDDHHMMSSZ'
	 * - GeneralizedTime: 'YYYYMMDDHHMMSSZ'
	 *
	 * @param aString string no formato UTCTime ou GeneralizedTime.
	 *
	 * @return Data no formato epoch em um BigInteger.
	 *
	 * @throw out_of_range if month, day, hour, min or sec is out of range.
	 **/
	static BigInteger date2epoch(const std::string& aString) throw()
	{
		uint32_t year;
		uint32_t month;	// [0-11]
		uint32_t day;	// [1-31]
		uint32_t hour;	// [0-23]
		uint32_t min;	// [0-59]
		uint32_t sec;	// [0-59]  + TODO: leap second?
		bool utc = false;
		std::istringstream stream;
		uint32_t gtoffset = 0; // deslocamento adicionar para substring se for generalizedtime
		
		utc = aString.size() == 13;
		
		// year
		if(utc) {
			stream.str(aString.substr(0,2));
			stream >> year;
			
			if(year >= 50) {
				year+= 1900;
			} else {
				year+= 2000;
			}			
		} else { //gt
			stream.str(aString.substr(0,4));
			stream >> year;
			gtoffset = 2;
		}
		
		// month
		stream.clear();
		stream.str(aString.substr(2 + gtoffset,2));
		stream >> month;
		month--;
		THROW_OUT_OF_RANGE_IF(month > 11);

		// day
		stream.clear();
		stream.str(aString.substr(4 + gtoffset,2));
		stream >> day;
		THROW_OUT_OF_RANGE_IF(day < 1 || day > DateTime::getMonthSize(month, year));

		// hour
		stream.clear();
		stream.str(aString.substr(6 + gtoffset,2));
		stream >> hour;
		THROW_OUT_OF_RANGE_IF(hour > 23);
		
		// min
		stream.clear();
		stream.str(aString.substr(8 + gtoffset,2));
		stream >> min;
		THROW_OUT_OF_RANGE_IF(min > 59);
		
		// sec
		stream.clear();
		stream.str(aString.substr(10 + gtoffset,2));
		stream >> sec;
		THROW_OUT_OF_RANGE_IF(sec > 59);

		return date2epoch(year, month, day, hour, min, sec);
	}
	
	/**
	 * @brief Transforma do formato ano, mês, dia, hora, minuto, e segundo (Zulu/GMT+0) para epoch.
	 *
	 * @param year Ano.
	 * @param month Mês [0-11]
	 * @param day Dia [1-31]
	 * @param hour Hora [0-23]
	 * @param min Minuto [0-59]
	 * @param sec Segundo [0-59]
	 *
	 * @return Data no formato epoch em um BigInteger.
	 *
	 * @throw out_of_range if month, day, hour, min or sec is out of range.
	 **/
	static BigInteger date2epoch(uint32_t year, uint32_t month, uint32_t day, uint32_t hour,
			uint32_t min, uint32_t sec) throw()
	{
		THROW_OUT_OF_RANGE_IF(month > 11 || day < 1 || day > DateTime::getMonthSize(month, year) ||
				hour > 23 || min > 59 || sec > 59);

		BigInteger ret(0L);
		
		for(uint32_t i = 1970; i < year; i++) {
			ret.add(DateTime::getYearSize(i));
		}
		
		for(uint32_t i = 0 ; i < month ; i ++) {
			ret.add(DateTime::getMonthSize(i, year));
		}
		
		ret.add(day - 1);	
		ret.mul(24);
		ret.add(hour);
		ret.mul(60);
		ret.add(min);
		ret.mul(60);
		ret.add(sec);
			
		return ret;
	}
	
	/***
	 * @brief Retorna o dia da semana dados ano, mês e dia.
	 *
	 * Código baseado em: http://www.sislands.com/coin70/week3/dayofwk.htm
	 *
	 * @param year Ano.
	 * @param month Mês [0-11]
	 * @param day Dia [1-31]
	 *
	 * @return dia da semana: 0 para Domingo, 6 para Sábado.
	 *
	 * @throw out_of_range if month or day is out of range.
	 **/
	static uint32_t getDayOfWeek(uint32_t year, uint32_t month, uint32_t day) throw()
	{
		THROW_OUT_OF_RANGE_IF(month > 11 || day < 1 || day > DateTime::getMonthSize(month, year));

		month++; // para adaptar ao algoritmo
		uint32_t a = (14 - month) / 12;
		uint32_t y = year - a;
		uint32_t m = month + 12 * a - 2;
		return (day + y + (y / 4) - (y / 100) + (y / 400) + ((31 * m) / 12))  % 7;		
	}
	
	/**
	 * @brief Verifica se um ano é bissexto.
	 *
	 * @param year Ano.
	 *
	 * @return true se é bissexto, false caso contrário.
	 * */
	inline static bool isLeapYear(uint32_t year)
	{
		return (year > 0) && !(year % 4) && ( (year % 100) || !(year % 400) );
	}

	/**
	 * #brief Retorna quantidade de dias de um ano.
	 *
	 * @param year Ano desejado.
	 *
	 * @return Número de dias.
	 **/
	static uint32_t getYearSize(uint32_t year)
	{
		return 365 + (DateTime::isLeapYear(year) ? 1 : 0);
	}
	
	/**
	 * @brief Retorna quantidade de dias de um mês em um ano.
	 *
	 * @param month Mês [0-11].
	 * @param year Ano desejado.
	 *
	 * @return número de dias no mês e ano escolhido.
	 *
	 * @throw out_of_range if month is out of range.
	 * */
	static uint32_t getMonthSize(uint32_t month, uint32_t year) throw()
	{
		THROW_OUT_OF_RANGE_IF(month > 11);

		uint32_t daysOfMonths[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

		uint32_t ret = daysOfMonths[month];
		
		if( (DateTime::isLeapYear(year)) && (month == 1) ) {
			ret++;
		}
		
		return ret;
	}

protected:
	/* Segundos desde 00:00:00 on January 1, 1970, Coordinated Universal Time (UTC). */
	BigInteger seconds;
};

#endif /*DATETIME_H_*/
