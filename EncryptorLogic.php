<?php
/**
 * 数据通信加解密工具类
 *
 * @copyright   Copyright © 2019 枫芒科技
 * @author      wangguanqun <wangguanqun@fmtech.me>
 * @version     1.0.0
 * @link        http://www.fmtech.me
 */

include_once "AESLogic.php";
include_once "EncryptorException.php";

class EncryptorLogic
{
    /*
    |--------------------------------------------------------------------------
    | Encryptor Logic
    |--------------------------------------------------------------------------
    |
    | 数据通信加解密工具的业务逻辑，包含加密encrypt、解密decrypt
    |
    */

    const ERROR_INVALID_SIGNATURE = -10001; // 签名校验错误
    const ERROR_INVALID_COMPANY_KEY = -10002; // 企业标识校验错误
    const ERROR_ENCRYPT_AES = -10003; // 加密失败
    const ERROR_DECRYPT_AES = -10005; // 解密失败
    const ERROR_ILLEGAL_BUFFER = -10006; // 解密后得到的buffer非法

    /**
     * 企业标识.
     *
     * @var string
     */
    protected $companyKey;

    /**
     * 用于计算签名的 token
     *
     * @var string
     */
    protected $token;

    /**
     * 未被base64编码的 aesKey
     *
     * @var string
     */
    protected $aesKey;

    /**
     * 块大小（字节）
     *
     * @var int
     */
    protected $blockSize = 32;

    /**
     * 构造方法
     *
     * @param string $companyKey 企业标识
     * @param string $token 用于计算签名的 token
     * @param string $encodingAESKey 经过 base64 编码的 AESKey
     */
    public function __construct($companyKey, $token, $encodingAESKey)
    {
        $this->companyKey = $companyKey;
        $this->token = $token;
        $this->aesKey = base64_decode($encodingAESKey.'=', true);
    }

    /**
     * 加密需要发送的消息
     *
     * @param string $msg 待加密的明文消息
     * @param string $nonce 随机数
     * @param int $timestamp 时间戳
     * @return array 加密后用来发送的数组信息（包含加密字符串、签名、时间戳、随机数）
     * @throws EncryptorException
     */
    public function encrypt($msg, $nonce = null, $timestamp = null)
    {
        // 明文字符串由16个字节的随机字符串、4个字节的 msg 长度、明文 msg 和 companyKey 拼接组成。
        // 其中 msg 长度为 msg 的字节数，网络字节序；companyKey 为企业标识；
        // 将拼接的字符串采用 PKCS#7 填充，长度扩充至32字节的倍数
        try {
            $pkcs7Str = $this->pkcs7Pad($this->getRandomStr(16) . pack('N', strlen($msg)) . $msg . $this->companyKey);

            // 使用 AES-256-CBC 密码学方式加密字符串，然后使用 base64 编码
            $encrypted = base64_encode(AESLogic::encrypt(
                $pkcs7Str,
                $this->aesKey,
                substr($this->aesKey, 0, 16),
                OPENSSL_NO_PADDING
            ));
        } catch (\Throwable $e) {
            throw new EncryptorException($e->getMessage(), self::ERROR_ENCRYPT_AES);
        }

        !is_null($nonce) || $nonce = mt_rand(10000000, 999999999);
        !is_null($timestamp) || $timestamp = time();

        $response = [
            'encrypt' => $encrypted,
            'msgSignature' => $this->signature($this->token, $timestamp, $nonce, $encrypted),
            'timestamp' => $timestamp,
            'nonce' => $nonce,
        ];

        return $response;
    }

    /**
     * 解密收到的消息
     *
     * @param string $content 已加密的内容
     * @param string $msgSignature 签名
     * @param string $nonce 随机数
     * @param string $timestamp 时间戳
     * @return string 解密后的明文，如果是 get 请求验证地址，是一个普通字符串；如果是post请求，是一个json字符串
     * @throws EncryptorException
     */
    public function decrypt($content, $msgSignature, $nonce, $timestamp)
    {
        // 生成签名并验证
        $signature = $this->signature($this->token, $timestamp, $nonce, $content);
        if ($signature !== $msgSignature) {
            throw new EncryptorException('Invalid Signature.', self::ERROR_INVALID_SIGNATURE);
        }

        try {
            $decrypted = AESLogic::decrypt(
                base64_decode($content, true),
                $this->aesKey,
                substr($this->aesKey, 0, 16),
                OPENSSL_NO_PADDING
            );
        } catch (\Throwable $e) {
            throw new EncryptorException($e->getMessage(), self::ERROR_DECRYPT_AES);
        }

        try {
            $result = $this->pkcs7Unpad($decrypted);
            $content = substr($result, 16, strlen($result));
            $contentLen = unpack('N', substr($content, 0, 4))[1];
        } catch (\Throwable $e) {
            throw new EncryptorException($e->getMessage(), self::ERROR_ILLEGAL_BUFFER);
        }

        // 验证 companyKey
        if (trim(substr($content, $contentLen + 4)) !== $this->companyKey) {
            throw new EncryptorException('Invalid companyKey.', self::ERROR_INVALID_COMPANY_KEY);
        }

        return substr($content, 4, $contentLen);
    }

    /**
     * 返回指定长度的随机字符串，只包含大小字母和数字
     *
     * @param int $len 需要返回的字符串长度
     * @return string
     */
    public function getRandomStr($len)
    {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $max = strlen($chars)-1;
        $str = '';
        for ($i=0; $i<$len; $i++) {
            $str .= $chars[mt_rand(0, $max)];
        }
        return $str;
    }

    /**
     * 将接收到的参数按字典序排序，拼接后，使用 SHA1 加密，生成签名
     *
     * @return string
     */
    public function signature()
    {
        $array = func_get_args();
        sort($array, SORT_STRING);

        return sha1(implode($array));
    }

    /**
     * 将字符串使用 PKCS#7 pad 方法填充，使长度至32字节的倍数
     *
     * @param string $text 待填充的原始内容
     * @return string 填充后的内容
     */
    public function pkcs7Pad($text)
    {
        $padding = $this->blockSize - (strlen($text) % $this->blockSize);
        $pattern = chr($padding);

        return $text.str_repeat($pattern, $padding);
    }

    /**
     * 使用 PKCS#7 unpad 方法将多余的字符去掉
     *
     * @param string $text 待截取的已被填充的内容
     * @return string 截取后的内容
     */
    public function pkcs7Unpad($text)
    {
        $pad = ord(substr($text, -1));
        if ($pad < 1 || $pad > $this->blockSize) {
            $pad = 0;
        }

        return substr($text, 0, (strlen($text) - $pad));
    }
}
