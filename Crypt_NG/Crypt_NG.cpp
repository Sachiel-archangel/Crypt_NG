// Crypt_NG.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include "pch.h"
#include <iostream>
#include "DataContainer.h"
#include "AES128.h"

static const BYTE bAES128SampleKey[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};



int main()
{
	DataContainer objKey;
	DataContainer objData;
	DataContainer objIV;

	// ダミーデータ設定
	objKey.CreateDataObject(16);
	objKey.SetCurrentDataSize(16);
	memcpy(objKey.GetDataPointer(), bAES128SampleKey, 16);

	objData.CreateDataObject(64);
	wcscpy_s((wchar_t*)objData.GetDataPointer(), 64, (const wchar_t*)L"Test Data for Encrypt");
	objData.SetCurrentDataSize(lstrlenW((LPCWSTR)objData.GetDataPointer()) * 2 + 2);


//    std::cout << "Hello World!\n"; 
//	AES128::Encrypt(&objKey, &objData, AES128_MODE_GCM);
	AES128::EncryptECB(&objKey, &objData);

//	AES128::Decrypt(&objKey, &objData, AES128_MODE_GCM);
	AES128::DecryptECB(&objKey, &objData);



	// ダミーデータ設定
	objKey.CreateDataObject(16);
	objKey.SetCurrentDataSize(16);
	memcpy(objKey.GetDataPointer(), bAES128SampleKey, 16);

	objData.CreateDataObject(64);
	wcscpy_s((wchar_t*)objData.GetDataPointer(), 64, (const wchar_t*)L"Test Data for Encrypt");
	objData.SetCurrentDataSize(lstrlenW((LPCWSTR)objData.GetDataPointer()) * 2 + 2);

	objIV.CreateDataObject(16);
	objIV.SetCurrentDataSize(16);


	AES128::EncryptCBC(&objKey, &objData, &objIV);

	AES128::DecryptCBC(&objKey, &objData, &objIV);


	objKey.DeleteDataObject();
	objData.DeleteDataObject();

	return 0;
}

// プログラムの実行: Ctrl + F5 または [デバッグ] > [デバッグなしで開始] メニュー
// プログラムのデバッグ: F5 または [デバッグ] > [デバッグの開始] メニュー

// 作業を開始するためのヒント: 
//    1. ソリューション エクスプローラー ウィンドウを使用してファイルを追加/管理します 
//   2. チーム エクスプローラー ウィンドウを使用してソース管理に接続します
//   3. 出力ウィンドウを使用して、ビルド出力とその他のメッセージを表示します
//   4. エラー一覧ウィンドウを使用してエラーを表示します
//   5. [プロジェクト] > [新しい項目の追加] と移動して新しいコード ファイルを作成するか、[プロジェクト] > [既存の項目の追加] と移動して既存のコード ファイルをプロジェクトに追加します
//   6. 後ほどこのプロジェクトを再び開く場合、[ファイル] > [開く] > [プロジェクト] と移動して .sln ファイルを選択します
