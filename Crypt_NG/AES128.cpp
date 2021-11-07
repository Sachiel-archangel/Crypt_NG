#include "pch.h"
#include "AES128.h"
#include <bcrypt.h>
#include <stdio.h>

AES128::AES128()
{
}


AES128::~AES128()
{
}

int AES128::Encrypt(DataContainer *pobjKey, DataContainer *pobjData, DataContainer *pobjIV, int iMode)
{
	// 参考：
	// https://docs.microsoft.com/en-us/windows/win32/seccng/encrypting-data-with-cng
	// Bcrypt.libをリンクすること。

	if(iMode == AES128_MODE_ECB)
	{
		return EncryptECB(pobjKey, pobjData);
	}
	
	else if (iMode == AES128_MODE_CBC)
	{
		return EncryptCBC(pobjKey, pobjData, pobjIV);
	}

	return AES128_ERROR;
}


int AES128::Decrypt(DataContainer *pobjKey, DataContainer *pobjData, DataContainer *pobjIV, int iMode)
{
	if (iMode == AES128_MODE_ECB)
	{
		return DecryptECB(pobjKey, pobjData);
	}

	else if (iMode == AES128_MODE_CBC)
	{
		return DecryptCBC(pobjKey, pobjData, pobjIV);
	}

	return AES128_ERROR;
}


int AES128::EncryptECB(DataContainer *pobjKey, DataContainer *pobjData)
{
	int retcode = AES128_ERROR;
	NTSTATUS	status;
	BCRYPT_ALG_HANDLE	hAesAlg = NULL;
	BCRYPT_KEY_HANDLE	hKey = NULL;

	// 引数チェック
	if (pobjKey == NULL || pobjData == NULL)
	{
		return AES128_ERROR;
	}

	do {
		// (1) BCryptOpenAlgorithmProvider
		// プロバイダオブジェクトの取得
		status = BCryptOpenAlgorithmProvider(
			&hAesAlg,
			BCRYPT_AES_ALGORITHM,
			NULL,
			0);
		if (status < 0)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error 0x%x returned by EncryptECB:BCryptOpenAlgorithmProvider\n", status);
#endif // OUTPUT_STDMESSAGE

			break;
		}

		// (2) BCryptSetProperty
		// 暗号化モードを設定する。
		status = BCryptSetProperty(
			hAesAlg,
			BCRYPT_CHAINING_MODE,
			(PBYTE)BCRYPT_CHAIN_MODE_ECB,
			sizeof(BCRYPT_CHAIN_MODE_ECB),
			0);
		if (status < 0)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error 0x%x returned by EncryptECB:BCryptSetProperty\n", status);
#endif // OUTPUT_STDMESSAGE

			break;
		}


		// (3) BCryptImportKey
		// 鍵をインポートする。
		hKey = ImportKey(hAesAlg, pobjKey);

		if (hKey == NULL)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error EncryptECB:ImportKey\n");
#endif // OUTPUT_STDMESSAGE

			break;
		}


		// (4) BCryptEncrypt
		// 暗号化の結果を受け取るサイズを取得する。
		if (EncryptECBWrap(hKey, pobjData) != AES128_SUCCESS)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error EncryptECB:ImportKey\n");
#endif // OUTPUT_STDMESSAGE

			break;
		}

		// ここまで来た場合、リターン値を「成功」とする。
		retcode = AES128_SUCCESS;

	} while (0);

	// (5) BCryptCloseAlgorithmProvider, BCryptDestroyKey
	// オブジェクトの開放
	if (hAesAlg)
	{
		BCryptCloseAlgorithmProvider(hAesAlg, 0);
	}

	if (hKey)
	{
		BCryptDestroyKey(hKey);
	}

	return AES128_SUCCESS;
}


int AES128::DecryptECB(DataContainer *pobjKey, DataContainer *pobjData)
{
	int retcode = AES128_ERROR;
	NTSTATUS	status;
	BCRYPT_ALG_HANDLE	hAesAlg = NULL;
	BCRYPT_KEY_HANDLE	hKey = NULL;

	// 引数チェック
	if (pobjKey == NULL || pobjData == NULL)
	{
		return AES128_ERROR;
	}

	do {
		// (1) BCryptOpenAlgorithmProvider
		// プロバイダオブジェクトの取得
		status = BCryptOpenAlgorithmProvider(
			&hAesAlg,
			BCRYPT_AES_ALGORITHM,
			NULL,
			0);
		if (status < 0)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error 0x%x returned by DecryptECB:BCryptOpenAlgorithmProvider\n", status);
#endif // OUTPUT_STDMESSAGE

			break;
		}

		// (2) BCryptSetProperty
		// 暗号化モードを設定する。
		status = BCryptSetProperty(
			hAesAlg,
			BCRYPT_CHAINING_MODE,
			(PBYTE)BCRYPT_CHAIN_MODE_ECB,
			sizeof(BCRYPT_CHAIN_MODE_ECB),
			0);
		if (status < 0)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error 0x%x returned by DecryptECB:BCryptSetProperty\n", status);
#endif // OUTPUT_STDMESSAGE

			break;
		}


		// (3) BCryptImportKey
		// 鍵をインポートする。
		hKey = ImportKey(hAesAlg, pobjKey);

		if (hKey == NULL)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error DecryptECB:ImportKey\n");
#endif // OUTPUT_STDMESSAGE

			break;
		}


		// (4) BCryptDecrypt関数
		if (DecryptECBWrap(hKey, pobjData) != AES128_SUCCESS)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error DecryptECB:ImportKey\n");
#endif // OUTPUT_STDMESSAGE

			break;
		}

		// ここまで来た場合、リターン値を「成功」とする。
		retcode = AES128_SUCCESS;

	} while (0);


	// (5) BCryptCloseAlgorithmProvider, BCryptDestroyKey
	// オブジェクトの開放
	if (hAesAlg)
	{
		BCryptCloseAlgorithmProvider(hAesAlg, 0);
	}

	if (hKey)
	{
		BCryptDestroyKey(hKey);
	}

	return retcode;
}


int AES128::EncryptCBC(DataContainer *pobjKey, DataContainer *pobjData, DataContainer *pobjIV)
{
	int retcode = AES128_ERROR;
	NTSTATUS	status;
	BCRYPT_ALG_HANDLE	hAesAlg = NULL;
	BCRYPT_KEY_HANDLE	hKey = NULL;

	// 引数チェック
	if (pobjKey == NULL || pobjData == NULL || pobjIV == NULL)
	{
		return AES128_ERROR;
	}

	do {
		// (1) BCryptOpenAlgorithmProvider
		// プロバイダオブジェクトの取得
		status = BCryptOpenAlgorithmProvider(
			&hAesAlg,
			BCRYPT_AES_ALGORITHM,
			NULL,
			0);
		if (status < 0)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error 0x%x returned by EncryptCBC:BCryptOpenAlgorithmProvider\n", status);
#endif // OUTPUT_STDMESSAGE

			break;
		}


		// (2) BCryptSetProperty
		// 暗号化モードを設定する。
		status = BCryptSetProperty(
			hAesAlg,
			BCRYPT_CHAINING_MODE,
			(PBYTE)BCRYPT_CHAIN_MODE_CBC,
			sizeof(BCRYPT_CHAIN_MODE_CBC),
			0);
		if (status < 0)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error 0x%x returned by EncryptCBC:BCryptSetProperty\n", status);
#endif // OUTPUT_STDMESSAGE

			break;
		}


		// (3) BCryptImportKey
		// 鍵をインポートする。
		hKey = ImportKey(hAesAlg, pobjKey);

		if (hKey == NULL)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error EncryptCBC:ImportKey\n");
#endif // OUTPUT_STDMESSAGE

			break;
		}


		// (4) BCryptEncrypt
		// 暗号化の結果を受け取るサイズを取得する。
		if (EncryptCBCWrap(hKey, pobjData, pobjIV) != AES128_SUCCESS)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error EncryptECB:ImportKey\n");
#endif // OUTPUT_STDMESSAGE

			break;
		}

		// ここまで来た場合、リターン値を「成功」とする。
		retcode = AES128_SUCCESS;


	} while (0);


	// (5) BCryptCloseAlgorithmProvider, BCryptDestroyKey
	// オブジェクトの開放
	if (hAesAlg)
	{
		BCryptCloseAlgorithmProvider(hAesAlg, 0);
	}

	if (hKey)
	{
		BCryptDestroyKey(hKey);
	}

	return retcode;
}


int AES128::DecryptCBC(DataContainer *pobjKey, DataContainer *pobjData, DataContainer *pobjIV)
{
	int retcode = AES128_ERROR;
	NTSTATUS	status;
	BCRYPT_ALG_HANDLE	hAesAlg = NULL;
	BCRYPT_KEY_HANDLE	hKey = NULL;

	// 引数チェック
	if (pobjKey == NULL || pobjData == NULL || pobjIV == NULL)
	{
		return AES128_ERROR;
	}

	do {
		// (1) BCryptOpenAlgorithmProvider
		// プロバイダオブジェクトの取得
		status = BCryptOpenAlgorithmProvider(
			&hAesAlg,
			BCRYPT_AES_ALGORITHM,
			NULL,
			0);
		if (status < 0)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error 0x%x returned by DecryptCBC:BCryptOpenAlgorithmProvider\n", status);
#endif // OUTPUT_STDMESSAGE

			break;
		}

		// (2) BCryptSetProperty
		// 暗号化モードを設定する。
		status = BCryptSetProperty(
			hAesAlg,
			BCRYPT_CHAINING_MODE,
			(PBYTE)BCRYPT_CHAIN_MODE_CBC,
			sizeof(BCRYPT_CHAIN_MODE_CBC),
			0);
		if (status < 0)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error 0x%x returned by DecryptCBC:BCryptSetProperty\n", status);
#endif // OUTPUT_STDMESSAGE

			break;
		}


		// (3) BCryptImportKey
		// 鍵をインポートする。
		hKey = ImportKey(hAesAlg, pobjKey);

		if (hKey == NULL)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error DecryptCBC:ImportKey\n");
#endif // OUTPUT_STDMESSAGE

			break;
		}


		// (4) BCryptDecrypt関数
		if (DecryptCBCWrap(hKey, pobjData, pobjIV) != AES128_SUCCESS)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error DecryptCBC:ImportKey\n");
#endif // OUTPUT_STDMESSAGE

			break;
		}

		// ここまで来た場合、リターン値を「成功」とする。
		retcode = AES128_SUCCESS;

	} while (0);


	// (5) BCryptCloseAlgorithmProvider, BCryptDestroyKey
	// オブジェクトの開放
	if (hAesAlg)
	{
		BCryptCloseAlgorithmProvider(hAesAlg, 0);
	}

	if (hKey)
	{
		BCryptDestroyKey(hKey);
	}

	return retcode;
}


BCRYPT_KEY_HANDLE AES128::ImportKey(BCRYPT_ALG_HANDLE hAesAlg, DataContainer *pobjKey)
{
	DataContainer	objKeyInput;
	NTSTATUS	status;
	BCRYPT_KEY_HANDLE	hKey;

	// インポートする鍵の情報をBCRYPT_KEY_DATA_BLOB_HEADER構造体のデータにするために、領域を確保する
	if (objKeyInput.CreateDataObject(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + pobjKey->GetCurrentDataSize()) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Allocate Error for ImportKey:CreateKeyBlobObject\n");
#endif // OUTPUT_STDMESSAGE

		return NULL;
	}

	// インポートする鍵の情報をBCRYPT_KEY_DATA_BLOB_HEADER構造体のデータにする。
	BCRYPT_KEY_DATA_BLOB_HEADER *pKeyHeader = (BCRYPT_KEY_DATA_BLOB_HEADER *)objKeyInput.GetDataPointer();
	pKeyHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
	pKeyHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
	pKeyHeader->cbKeyData = pobjKey->GetCurrentDataSize();
	memcpy((char *)objKeyInput.GetDataPointer() + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), pobjKey->GetDataPointer(), pobjKey->GetCurrentDataSize());
	objKeyInput.SetCurrentDataSize(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + pobjKey->GetCurrentDataSize());

	// インポート処理
	status = BCryptImportKey(
		hAesAlg,
		NULL,
		BCRYPT_KEY_DATA_BLOB,
		&hKey,
		NULL,
		NULL,
		(PUCHAR)objKeyInput.GetDataPointer(),
		objKeyInput.GetCurrentDataSize(),
		0);

	if (status < 0)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error 0x%x returned by ImportKey:BCryptImportKey\n", status);
#endif // OUTPUT_STDMESSAGE

		hKey = NULL;
	}

	objKeyInput.DeleteDataObject();

	return hKey;
}


int AES128::EncryptECBWrap(BCRYPT_KEY_HANDLE hKey, DataContainer *pobjData)
{
	NTSTATUS		status;
	DataContainer	objCipherOutput;
	DWORD			dwCipherOutputSize = 0;

	// (1) 暗号化結果のサイズを求める。
	status = BCryptEncrypt(
		hKey,
		(PUCHAR)pobjData->GetDataPointer(),
		pobjData->GetCurrentDataSize(),
		NULL,
		NULL,
		0,
		NULL,
		0,
		&dwCipherOutputSize,
		BCRYPT_BLOCK_PADDING
	);
	if (status < 0)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error 0x%x returned by EncryptECBWrap:BCryptEncrypt(for getting size)\n", status);
#endif // OUTPUT_STDMESSAGE

		return AES128_ERROR;
	}

	// (2) 暗号化結果受け取り用領域確保
	if (objCipherOutput.CreateDataObject(dwCipherOutputSize) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Allocate Error for EncryptECBWrap:objCipherOutput\n");
#endif // OUTPUT_STDMESSAGE

		return AES128_ERROR;
	}

	// (3) 暗号化する。
	status = BCryptEncrypt(
		hKey,
		(PUCHAR)pobjData->GetDataPointer(),
		pobjData->GetCurrentDataSize(),
		NULL,
		NULL,
		0,
		(PUCHAR)objCipherOutput.GetDataPointer(),
		objCipherOutput.GetDataSize(),
		&dwCipherOutputSize,
		BCRYPT_BLOCK_PADDING
	);
	if (status < 0)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error 0x%x returned by EncryptECBWrap:BCryptEncrypt(for encryption)\n", status);
#endif // OUTPUT_STDMESSAGE

		objCipherOutput.DeleteDataObject();
		return AES128_ERROR;
	}


	// (4) 結果を出力のためにコピーする。
	if (pobjData->ReallocDataObject(dwCipherOutputSize) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Allocate Error for pobjData\n");
#endif // OUTPUT_STDMESSAGE

		objCipherOutput.DeleteDataObject();
		return AES128_ERROR;
	}

	memcpy(pobjData->GetDataPointer(), objCipherOutput.GetDataPointer(), dwCipherOutputSize);
	pobjData->SetCurrentDataSize(dwCipherOutputSize);

	objCipherOutput.DeleteDataObject();

	return AES128_SUCCESS;
}

int AES128::DecryptECBWrap(BCRYPT_KEY_HANDLE hKey, DataContainer *pobjData)
{
	NTSTATUS		status;
	DataContainer	objCipherOutput;
	DWORD			dwCipherOutputSize = 0;


	// (1) 復号化の結果を受け取るサイズを取得する。
	status = BCryptDecrypt(
		hKey,
		(PUCHAR)pobjData->GetDataPointer(),
		pobjData->GetCurrentDataSize(),
		NULL,
		NULL,
		0,
		NULL,
		0,
		&dwCipherOutputSize,
		BCRYPT_BLOCK_PADDING
	);
	if (status < 0)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error 0x%x returned by DecryptECBWrap:BCryptDecrypt(for getting size)\n", status);
#endif // OUTPUT_STDMESSAGE

		return AES128_ERROR;
	}

	// (2) 復号化結果受け取り用領域確保
	if (objCipherOutput.CreateDataObject(dwCipherOutputSize) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Allocate Error for DecryptECBWrap:objCipherOutput\n");
#endif // OUTPUT_STDMESSAGE

		return AES128_ERROR;
	}

	// (3) 復号化する。
	status = BCryptDecrypt(
		hKey,
		(PUCHAR)pobjData->GetDataPointer(),
		pobjData->GetCurrentDataSize(),
		NULL,
		NULL,
		0,
		(PUCHAR)objCipherOutput.GetDataPointer(),
		objCipherOutput.GetDataSize(),
		&dwCipherOutputSize,
		BCRYPT_BLOCK_PADDING
	);
	if (status < 0)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error 0x%x returned by DecryptECBWrap:BCryptDecrypt(for decryption)\n", status);
#endif // OUTPUT_STDMESSAGE

		objCipherOutput.DeleteDataObject();
		return AES128_ERROR;
	}


	// (4) 結果を出力のためにコピーする。
	if (pobjData->ReallocDataObject(dwCipherOutputSize) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Allocate Error for DecryptECBWrap:pobjData\n");
#endif // OUTPUT_STDMESSAGE

		objCipherOutput.DeleteDataObject();
		return AES128_ERROR;
	}

	memcpy(pobjData->GetDataPointer(), objCipherOutput.GetDataPointer(), dwCipherOutputSize);
	pobjData->SetCurrentDataSize(dwCipherOutputSize);

	objCipherOutput.DeleteDataObject();

	return AES128_SUCCESS;
}


int AES128::EncryptCBCWrap(BCRYPT_KEY_HANDLE hKey, DataContainer *pobjData, DataContainer *pobjIV)
{
	NTSTATUS		status;
	DataContainer	objCipherOutput;
	DWORD			dwCipherOutputSize = 0;
	DataContainer	objIVLocal;


	// (1) IVをコピーする。
	// 理由：Encryptを実行した際、内容を書き換えられるため。
	if (objIVLocal.CreateDataObject(pobjIV->GetCurrentDataSize()) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error EncryptCBCWrap:objIVLocal.CreateDataObject\n");
#endif // OUTPUT_STDMESSAGE

		return AES128_ERROR;
	}

	if(objIVLocal.ImportData(pobjIV->GetDataPointer(), pobjIV->GetCurrentDataSize()) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error EncryptCBCWrap:objIVLocal.ImportData\n");
#endif // OUTPUT_STDMESSAGE

		objIVLocal.DeleteDataObject();
		return AES128_ERROR;
	}


	// (2) 暗号化結果のサイズを求める。
	status = BCryptEncrypt(
		hKey,
		(PUCHAR)pobjData->GetDataPointer(),
		pobjData->GetCurrentDataSize(),
		NULL,
		(PUCHAR)objIVLocal.GetDataPointer(),
		objIVLocal.GetCurrentDataSize(),
		NULL,
		0,
		&dwCipherOutputSize,
		BCRYPT_BLOCK_PADDING
	);
	if (status < 0)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error 0x%x returned by EncryptCBCWrap:BCryptEncrypt(for getting size)\n", status);
#endif // OUTPUT_STDMESSAGE

		objIVLocal.DeleteDataObject();
		return AES128_ERROR;
	}

	// (3) 暗号化結果受け取り用領域確保
	if (objCipherOutput.CreateDataObject(dwCipherOutputSize) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Allocate Error for EncryptCBCWrap:objCipherOutput\n");
#endif // OUTPUT_STDMESSAGE

		objIVLocal.DeleteDataObject();
		return AES128_ERROR;
	}


	// (4) 暗号化する。
	status = BCryptEncrypt(
		hKey,
		(PUCHAR)pobjData->GetDataPointer(),
		pobjData->GetCurrentDataSize(),
		NULL,
		(PUCHAR)objIVLocal.GetDataPointer(),
		objIVLocal.GetCurrentDataSize(),
		(PUCHAR)objCipherOutput.GetDataPointer(),
		objCipherOutput.GetDataSize(),
		&dwCipherOutputSize,
		BCRYPT_BLOCK_PADDING
	);
	if (status < 0)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error 0x%x returned by EncryptCBCWrap:BCryptEncrypt(for encryption)\n", status);
#endif // OUTPUT_STDMESSAGE

		objCipherOutput.DeleteDataObject();
		objIVLocal.DeleteDataObject();
		return AES128_ERROR;
	}


	// (5) 結果を出力のためにコピーする。
	if (pobjData->ReallocDataObject(dwCipherOutputSize) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Allocate Error for pobjData\n");
#endif // OUTPUT_STDMESSAGE

		objCipherOutput.DeleteDataObject();
		objIVLocal.DeleteDataObject();
		return AES128_ERROR;
	}

	memcpy(pobjData->GetDataPointer(), objCipherOutput.GetDataPointer(), dwCipherOutputSize);
	pobjData->SetCurrentDataSize(dwCipherOutputSize);

	objCipherOutput.DeleteDataObject();
	objIVLocal.DeleteDataObject();

	return AES128_SUCCESS;
}

int AES128::DecryptCBCWrap(BCRYPT_KEY_HANDLE hKey, DataContainer *pobjData, DataContainer *pobjIV)
{
	NTSTATUS		status;
	DataContainer	objCipherOutput;
	DWORD			dwCipherOutputSize = 0;
	DataContainer	objIVLocal;


	// (1) IVをコピーする。
	// 理由：Encryptを実行した際、内容を書き換えられるため。
	if (objIVLocal.CreateDataObject(pobjIV->GetCurrentDataSize()) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error DecryptCBCWrap:objIVLocal.CreateDataObject\n");
#endif // OUTPUT_STDMESSAGE

		return AES128_ERROR;
	}

	if (objIVLocal.ImportData(pobjIV->GetDataPointer(), pobjIV->GetCurrentDataSize()) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error DecryptCBCWrap:objIVLocal.ImportData\n");
#endif // OUTPUT_STDMESSAGE

		objIVLocal.DeleteDataObject();
		return AES128_ERROR;
	}


	// (2) 復号化の結果を受け取るサイズを取得する。
	status = BCryptDecrypt(
		hKey,
		(PUCHAR)pobjData->GetDataPointer(),
		pobjData->GetCurrentDataSize(),
		NULL,
		(PUCHAR)objIVLocal.GetDataPointer(),
		objIVLocal.GetCurrentDataSize(),
		NULL,
		0,
		&dwCipherOutputSize,
		BCRYPT_BLOCK_PADDING
	);
	if (status < 0)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error 0x%x returned by DecryptCBCWrap:BCryptDecrypt(for getting size)\n", status);
#endif // OUTPUT_STDMESSAGE

		objIVLocal.DeleteDataObject();
		return AES128_ERROR;
	}

	// (3) 復号化結果受け取り用領域確保
	if (objCipherOutput.CreateDataObject(dwCipherOutputSize) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Allocate Error for DecryptCBCWrap:objCipherOutput\n");
#endif // OUTPUT_STDMESSAGE

		objIVLocal.DeleteDataObject();
		return AES128_ERROR;
	}

	// (4) 復号化する。
	status = BCryptDecrypt(
		hKey,
		(PUCHAR)pobjData->GetDataPointer(),
		pobjData->GetCurrentDataSize(),
		NULL,
		(PUCHAR)objIVLocal.GetDataPointer(),
		objIVLocal.GetCurrentDataSize(),
		(PUCHAR)objCipherOutput.GetDataPointer(),
		objCipherOutput.GetDataSize(),
		&dwCipherOutputSize,
		BCRYPT_BLOCK_PADDING
	);
	if (status < 0)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Error 0x%x returned by DecryptCBCWrap:BCryptDecrypt(for decryption)\n", status);
#endif // OUTPUT_STDMESSAGE

		objCipherOutput.DeleteDataObject();
		objIVLocal.DeleteDataObject();
		return AES128_ERROR;
	}


	// (5) 結果を出力のためにコピーする。
	if (pobjData->ReallocDataObject(dwCipherOutputSize) != DATACONT_SUCCESS)
	{
#ifdef OUTPUT_STDMESSAGE
		wprintf(L"**** Allocate Error for DecryptCBCWrap:pobjData\n");
#endif // OUTPUT_STDMESSAGE

		objCipherOutput.DeleteDataObject();
		objIVLocal.DeleteDataObject();
		return AES128_ERROR;
	}

	memcpy(pobjData->GetDataPointer(), objCipherOutput.GetDataPointer(), dwCipherOutputSize);
	pobjData->SetCurrentDataSize(dwCipherOutputSize);

	objCipherOutput.DeleteDataObject();
	objIVLocal.DeleteDataObject();

	return AES128_SUCCESS;

}
