<?php
/**
 * 数据通信加解密示例
 *
 * @copyright   Copyright © 2019 枫芒科技
 * @author      wangguanqun <wangguanqun@fmtech.me>
 * @version     1.0.0
 * @link        http://www.fmtech.me
 */

include_once "EncryptorLogic.php";
include_once "EncryptorException.php";

// 假设企业在BOSS系统上的数据回调配置参数如下
$companyKey = "b9ca9a10-7878-11ea-ae73-00163e0a522b";
$url = 'https://your-website';
$token = "3ELgc0TvWB5X9bXqueBpE4sF2dJvX0";
$encodingAesKey = "cLU2SZiQtNTckwBYEbpgIj8bvj7Wjs6hY90DoFtNiBH";

/*
|--------------------------------------------------------------------------
| 示例一：验证回调URL
|--------------------------------------------------------------------------
|
| 企业在 BOSS 系统设置数据回调配置，点击保存时，BOSS系统会向数据回调 URL 发送一个 GET 请求，验证地址有效性
| GET https://your-website?msgSignature=53e2f8d0ba53cb7d49ffc9b42d88de3e1a666cad&timestamp=1586227726&nonce=817715303&encrypt=Yzl6eGlLandlMmtZajcyTkY0M1pEcHdlMmdWc0ZZQXR1Vmd5NHpsV1lKeFU0L2h3UnpCWGpya2dYNkdxK0NiTDVwRkJXOEQ2MUtnRFpua1l2TkNQdXN4M2N3YVJGdzRUdERaQlJOeUJBVzJlVWlDN3ZyNzlyWVplMmhKTllQMHI%3D
|
| 企业接收到请求后
| 1、解析出 GET 请求的参数，包括消息体签名(msgSignature)，时间戳(timestamp)，随机数(nonce)以及 BOSS 系统推送过来的加密字符串(encrypt),
|   这一步注意作URL解码。
| 2、验证消息体签名的正确性
| 3、解密出 encrypt 原文，将原文当作 GET 请求的 response，返回给 BOSS 系统
| 验证签名及解密，可以用 BOSS 系统提供的库函数 decrypt 实现
|
*/

// GET 请求的参数
$msgSignature = '53e2f8d0ba53cb7d49ffc9b42d88de3e1a666cad';
$timestamp = '1586227726';
$nonce = '817715303';
$encrypt = 'Yzl6eGlLandlMmtZajcyTkY0M1pEcHdlMmdWc0ZZQXR1Vmd5NHpsV1lKeFU0L2h3UnpCWGpya2dYNkdxK0NiTDVwRkJXOEQ2MUtnRFpua1l2TkNQdXN4M2N3YVJGdzRUdERaQlJOeUJBVzJlVWlDN3ZyNzlyWVplMmhKTllQMHI=';

// 需要返回的明文
$echoStr = '';

$encryptor = new EncryptorLogic($companyKey, $token, $encodingAesKey);
try {
    $echoStr = $encryptor->decrypt($encrypt, $msgSignature, $nonce, $timestamp);
    print("VerifyURL, echoStr: \n\n");
    echo $echoStr . "\n\n";
} catch (EncryptorException $e) {
    print("ERR: " . $e->getMessage() . "\n\n");
}
print("===============================\n\n");

/*
|--------------------------------------------------------------------------
| 示例二：解密 BOSS 系统推送的 POST 消息
|--------------------------------------------------------------------------
|
| 企业在 BOSS 系统成功设置数据回调后，在设备空间状态变更、设备在线状态变更、设备电池电量变更等情况下，BOSS系统会向数据回调 URL 发送一个 POST 请求，
| 推送变更消息，推送的变更消息经过 BOSS 系统加密，密文格式请参考官方文档
| POST https://your-website
|
| {
|   "msgSignature": "2bce89b7f32929e6506b73d85b36fbf87cf1d674",
|   "timestamp": 1586232017,
|   "nonce": 539071018,
|   "encrypt": "eTBLOEszcnk0LzlHUVBscHBBWDQrQ0l1bSttQnN5Q1JOc2lnL0xDaWxLdFpQSkIrNWVXd1B3MFRXaFI1Q0xKVTlXRVVFakMrcjQvSlRFZUpaanVXMkhOZkZRUS9GQXhraThJZHBwZnRBTHM4OVVaaElRUDZyNllqLzVTTWhvMHU0TGRGK3BMZkloOE8wbjVNZ2NxT1U4cmxzc2RWd2UxQ1B3Tm9CZm9aN09qMXdacmdzeCtldkZDN2JuU1NDcHVTOEpraElJcWpkbWR5dU9OV0ZpRitWenpFUHk5Z2FsQ1hJTjVraXhHbjF1dW1xaTEzaEFFOGdOWlMxNEVaa2tTbVVEUERmU0dOK1p2Zk1sKzlFclYyTnI3OWZXNkQrWHY1VjRYb0xlRVA2dWU2c3JzNm5rM1BGOHlnMnpqaE9lYjRxeHg5dXF3Z24xZmlHUWVZSS8vTFQ0MjRZcGdNZDEza3R2NXVzam9GcS9iSkZCT1VTZjVZci9zc1M0Q1RtcHRFcllYTXZnUGl4RGZMZm4zT1JmZnByL1RPMktSZXNkbDdVSE9nMWZ6MEEvS2p4KzYyVHZlKzk2R3NyTkN1T29OOTVHU1VqbW1tRnBQZ1BlT0VWMjByVVE9PQ==",
| }
|
| 企业接收到请求后
| 1、解析出 POST 请求的参数，包括消息体签名(msgSignature)，时间戳(timestamp)，随机数(nonce)以及 BOSS 系统推送过来的随机加密字符串(encrypt)
| 2、验证消息体签名的正确性
| 3、解密出 encrypt 原文，解密出来的明文是一个 json 字符串，需要转换成 json 对象，明文格式请参考官方文档
| 验证签名及解密，可以用 BOSS 系统提供的库函数 decrypt 实现
|
*/

// POST 请求的参数
$msgSignature = '2bce89b7f32929e6506b73d85b36fbf87cf1d674';
$timestamp = '1586232017';
$nonce = '539071018';
$encrypt = 'eTBLOEszcnk0LzlHUVBscHBBWDQrQ0l1bSttQnN5Q1JOc2lnL0xDaWxLdFpQSkIrNWVXd1B3MFRXaFI1Q0xKVTlXRVVFakMrcjQvSlRFZUpaanVXMkhOZkZRUS9GQXhraThJZHBwZnRBTHM4OVVaaElRUDZyNllqLzVTTWhvMHU0TGRGK3BMZkloOE8wbjVNZ2NxT1U4cmxzc2RWd2UxQ1B3Tm9CZm9aN09qMXdacmdzeCtldkZDN2JuU1NDcHVTOEpraElJcWpkbWR5dU9OV0ZpRitWenpFUHk5Z2FsQ1hJTjVraXhHbjF1dW1xaTEzaEFFOGdOWlMxNEVaa2tTbVVEUERmU0dOK1p2Zk1sKzlFclYyTnI3OWZXNkQrWHY1VjRYb0xlRVA2dWU2c3JzNm5rM1BGOHlnMnpqaE9lYjRxeHg5dXF3Z24xZmlHUWVZSS8vTFQ0MjRZcGdNZDEza3R2NXVzam9GcS9iSkZCT1VTZjVZci9zc1M0Q1RtcHRFcllYTXZnUGl4RGZMZm4zT1JmZnByL1RPMktSZXNkbDdVSE9nMWZ6MEEvS2p4KzYyVHZlKzk2R3NyTkN1T29OOTVHU1VqbW1tRnBQZ1BlT0VWMjByVVE9PQ==';

// 解密出来的明文
$jsonStr = '';

$encryptor = new EncryptorLogic($companyKey, $token, $encodingAesKey);
try {
    $jsonStr = $encryptor->decrypt($encrypt, $msgSignature, $nonce, $timestamp);
    print("Decrypt, jsonStr: \n\n");
    print_r(json_decode($jsonStr, true));
} catch (EncryptorException $e) {
    print("ERR: " . $e->getMessage() . "\n\n");
}
print("===============================\n\n");

/*
|--------------------------------------------------------------------------
| 示例三：加密消息
|--------------------------------------------------------------------------
|
| 企业如果需要向 BOSS 系统 POST 加密消息，按如下方法组装数据
| 假如推送的数据明文如下（通常由数组转为json字符串）
|
| {
|   "msgType": "change_space_status",
|   "data": {
|      "deviceName": "d896e0ff10023d5c",
|      "applicationKey": "meeting",
|      "companyKey": "b9ca9a10-7878-11ea-ae73-00163e0a522b",
|      "spaceId": 1,
|      "spaceStatus": 1,
|      "purpose": "DETECTOR",
|      "lastReportTime": "2020-03-30 12:30:01",
|    },
|   "createTime": 1585542601
| }
|
| 1、将json字符串明文、企业标识CompanyKey加密得到密文
| 2、生成时间戳(timestamp)、随机数(nonce)，使用加密 token、步骤1得到的密文，生成消息体签名
| 3、将密文，消息体签名、时间戳、随机数拼接成 json 格式的字符串，POST 给 BOSS系统
| 加密过程可以用 BOSS 系统提供的库函数 encrypt 实现
|
*/

// 需要发送的明文
$sendData =  [
    'msgType' => 'change_space_status',
    'data' => [
        'deviceName' => 'd896e0ff10023d5c',
        'applicationKey' => 'meeting',
        'companyKey' => 'b9ca9a10-7878-11ea-ae73-00163e0a522b',
        'spaceId' => 1,
        'spaceStatus' => 1,
        'purpose' => 'DETECTOR',
        'lastReportTime' => '2020-03-30 12:30:01',
    ],
    'createTime' => 1585542601
];
$sendJsonStr = json_encode($sendData);

$encryptor = new EncryptorLogic($companyKey, $token, $encodingAesKey);
try {
    $sendArr = $encryptor->encrypt($sendJsonStr);
    print("Encrypt, sendArr: \n\n");
    print_r($sendArr);
} catch (EncryptorException $e) {
    print("ERR: " . $e->getMessage() . "\n\n");
}
print("===============================\n\n");
