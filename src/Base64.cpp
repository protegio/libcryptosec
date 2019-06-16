#include <libcryptosec/Base64.h>

#include <libcryptosec/ByteArray.h>

const std::string Base64::base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64::encode(const ByteArray& data)
{
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];
	
	unsigned int in_len = data.getSize();
	const unsigned char *bytes_to_encode = data.getConstDataPointer();
	
	while (in_len--)
	{
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3)
		{
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;
	
			for(i = 0; i < 4; i++) {
				ret += Base64::base64Chars[char_array_4[i]];
			}

			i = 0;
		}
	}
	
	if (i)
	{
		for(j = i; j < 3; j++)
			char_array_3[j] = '\0';
	
		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;
	
		for (j = 0; (j < i + 1); j++)
			ret += Base64::base64Chars[char_array_4[j]];
	
		while((i++ < 3))
			ret += '=';
	}
	return ret;
}

ByteArray Base64::decode(const std::string& data)
{
	int in_len = data.size();
	int max_out_len = (in_len/4)*3;
	int i = 0;
	int j = 0;
	int counter = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	ByteArray ret(max_out_len);

	while (in_len-- && ( data[in_] != '=') 
  		&& (isalnum(data[in_]) || (data[in_] == '+') || (data[in_] == '/')))
  	{
    
    	char_array_4[i++] = data[in_]; in_++;
		if (i == 4)
		{
			for (i = 0; i < 4; i++)
				char_array_4[i] = Base64::base64Chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
			{
				(ret.getDataPointer())[counter] = char_array_3[i];
				counter++;
			}
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j <4; j++)
			char_array_4[j] = 0;

		for (j = 0; j <4; j++)
			char_array_4[j] = Base64::base64Chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++)
		{
			(ret.getDataPointer())[counter] = char_array_3[j];
			counter++;
		}
	}

	ret.setSize(ret.getSize() - (in_len+1));
	return ret;
}
