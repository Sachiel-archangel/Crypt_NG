#pragma once
#include "DataContainer.h"

#define AES128_SUCCESS 0
#define AES128_ERROR -1

#define AES128_MODE_ECB 1
#define AES128_MODE_CBC 2
#define AES128_MODE_CFB 3
#define AES128_MODE_CCM 4
#define AES128_MODE_GCM 5



class AES128
{
public:
	AES128();
	~AES128();
	static int Encrypt(DataContainer *pobjKey, DataContainer *pobjData, DataContainer *pobjIV, int iMode);
	static int Decrypt(DataContainer *pobjKey, DataContainer *pobjData, DataContainer *pobjIV, int iMode);
	static int EncryptECB(DataContainer *pobjKey, DataContainer *pobjData);
	static int DecryptECB(DataContainer *pobjKey, DataContainer *pobjData);
	static int EncryptCBC(DataContainer *pobjKey, DataContainer *pobjData, DataContainer *pobjIV);
	static int DecryptCBC(DataContainer *pobjKey, DataContainer *pobjData, DataContainer *pobjIV);
	static int CreateIV(DataContainer *pobjIV);
	static int CreateKey(DataContainer *pobjIV);

private:
	static BCRYPT_KEY_HANDLE ImportKey(BCRYPT_ALG_HANDLE hAesAlg, DataContainer *pobjKey);
	static int EncryptECBWrap(BCRYPT_KEY_HANDLE hKey, DataContainer *pobjData);
	static int DecryptECBWrap(BCRYPT_KEY_HANDLE hKey, DataContainer *pobjData);
	static int EncryptCBCWrap(BCRYPT_KEY_HANDLE hKey, DataContainer *pobjData, DataContainer *pobjIV);
	static int DecryptCBCWrap(BCRYPT_KEY_HANDLE hKey, DataContainer *pobjData, DataContainer *pobjIV);
};

