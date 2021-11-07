#include "pch.h"
#include "Random.h"
#include <bcrypt.h>
#include <stdio.h>


Random::Random()
{
}


Random::~Random()
{
}


int Random::GenRandom(DataContainer *pobjData, int iSize)
{
	int iRetCode = RANDOM_ERROR;
	NTSTATUS	status;
	BCRYPT_ALG_HANDLE	hAesAlg = NULL;

	// 引数チェック
	if (pobjData == NULL || iSize <= 0)
	{
		return RANDOM_ERROR;
	}

	do {
		// (1) BCryptOpenAlgorithmProvider
		// プロバイダオブジェクトの取得
		status = BCryptOpenAlgorithmProvider(
			&hAesAlg,
			BCRYPT_RNG_ALGORITHM,
			NULL,
			0);
		if (status < 0)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error 0x%x returned by GenRandom:BCryptOpenAlgorithmProvider\n", status);
#endif // OUTPUT_STDMESSAGE

			break;
		}

		// (2) 受け取り領域の確保
		if(pobjData->CreateDataObject(iSize) != DATACONT_SUCCESS)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error GenRandom:CreateDataObject\n");
#endif // OUTPUT_STDMESSAGE

			break;
		}

		// (3) 乱数の作成
		status = BCryptGenRandom(
			hAesAlg,
			(PUCHAR)pobjData->GetDataPointer(),
			pobjData->GetDataSize(),
			0
		);
		if (status < 0)
		{
#ifdef OUTPUT_STDMESSAGE
			wprintf(L"**** Error 0x%x returned by GenRandom:BCryptGenRandom\n", status);
#endif // OUTPUT_STDMESSAGE

			pobjData->DeleteDataObject();
			break;
		}


		pobjData->SetCurrentDataSize(pobjData->GetDataSize());
		iRetCode = RANDOM_SUCCESS;

	} while (0);

	if (hAesAlg)
	{
		BCryptCloseAlgorithmProvider(hAesAlg, 0);
	}

	return iRetCode;
}