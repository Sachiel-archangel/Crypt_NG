# Crypt_NG

## Overview
Microsoft WindowsのCNG版の暗号化・復号化のサンプルソース。  
とりあえずAES128で試しに作成。
Sample encryption program using CNG of Microsoft Windows.  

## Concept
それぞれの関数は、単独で動くようにstatic関数で作成。  
そのため、繰り返し実行する場合はプロバイダオブジェクトの取得や鍵のインポート等でオーバーヘッドが出る。  
メンバ変数にハンドルなどを用意しておいて、インスタンス化するなどあると思うが、その辺りはお好みで。  

処理の記述も、それぞれのステップを分かりやすくすること、メンテナンス性が高い（いじりやすい、改造しやすい）ことを主眼にしている。  
そのため、速度やメモリの利用などの最適化を考える場合は、少々無駄がある。  
流用する場合は、個々の事情に合わせて最適化することをおススメする。  
（誰が見るんだ、こんなクソソース。）  

Each function is created as a static function so that it can operate independently.  
Therefore, if it is executed repeatedly, overhead will occur due to acquisition of provider object, import of key, etc.  

## Restriction
・エラー処理は十分ではない。  
　（あくまでCNGの動作を確認するためのサンプルコード）  
・大きなサイズのファイル/データについては考えていない。  
  
- Error handling is not enough.  
- It does not support large files/data.  
