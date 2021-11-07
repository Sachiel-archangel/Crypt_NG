// Crypt_NG.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include "pch.h"
#include <iostream>
#include "DataContainer.h"
#include "AES128.h"
#include "Random.h"



int main()
{
	DataContainer objKey;
	DataContainer objData;
	DataContainer objIV;
	DataContainer objRandom;


	// ダミーデータ設定
	objData.CreateDataObject(64);
	wcscpy_s((wchar_t*)objData.GetDataPointer(), 64, (const wchar_t*)L"Test Data for Encrypt");
	objData.SetCurrentDataSize(lstrlenW((LPCWSTR)objData.GetDataPointer()) * 2 + 2);

	// 鍵を乱数で作成
	AES128::CreateKey(&objKey);


	// 暗号化
	AES128::EncryptECB(&objKey, &objData);

	// 復号化
	AES128::DecryptECB(&objKey, &objData);



	// ダミーデータ設定
	objData.CreateDataObject(64);
	wcscpy_s((wchar_t*)objData.GetDataPointer(), 64, (const wchar_t*)L"Test Data for Encrypt");
	objData.SetCurrentDataSize(lstrlenW((LPCWSTR)objData.GetDataPointer()) * 2 + 2);

	// IVを乱数で作成
	AES128::CreateKey(&objIV);


	// 暗号化
	AES128::EncryptCBC(&objKey, &objData, &objIV);

	// 復号化
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
