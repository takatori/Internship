インターンシップ予習課題
====
pixiv 2015 SPRING BOOT CAMP 予習課題
* https://github.com/pixiv/intern2014w

## スコア
### 初期スコア
success:7720 fail:0 score:1668
### 最終スコア
success:29220 fail:6680: score:6312

## 行ったこと
### Redisの導入
ログイン失敗の判定をログインごとに毎回行っており、
その部分でのDB問い合わせに時間がかかっていると考えました。
そこで、ログの保存にMySQLを使用することをやめRedisを用いて実装し直しました。

## 参考
作業にあたり以下のサイトの解説を参考にさせていただきました。
* http://isucon.net/archives/40793620.html


