<?php
/**
 * 高级加密标准(AES)加解密类
 *
 * @copyright   Copyright © 2019 枫芒科技
 * @author      wangguanqun <wangguanqun@fmtech.me>
 * @version     1.0.0
 * @link        http://www.fmtech.me
 */

class AESLogic
{
    /*
    |--------------------------------------------------------------------------
    | AES Logic
    |--------------------------------------------------------------------------
    |
    | 高级加密标准(AES)加解密业务逻辑，AES采用CBC模式
    | IV初始向量大小为16字节，取AESKey前16字节
    |
    */

    /**
     * 加密方法：AES用CBC模式，密码长度由 $key 的长度决定，一般是32*8=256位
     *
     * @param string $text  要加密的内容
     * @param string $key   加密的AES key
     * @param string $iv    向量($key的前16位)
     * @param int    $option 是以下标记的按位或 OPENSSL_RAW_DATA OPENSSL_NO_PADDING
     * @return string 加密后的字符串
     */
    public static function encrypt($text, $key, $iv, $option = OPENSSL_RAW_DATA)
    {
        self::validateKey($key);
        self::validateIv($iv);

        return openssl_encrypt($text, self::getMode($key), $key, $option, $iv);
    }

    /**
     * 解密方法
     *
     * @param string      $cipherText   已被加密的密文
     * @param string      $key          解密的key
     * @param string      $iv           向量
     * @param int         $option       是以下标记的按位或 OPENSSL_RAW_DATA OPENSSL_ZERO_PADDING
     * @param string|null $method       密码学方式
     * @return string 解密后的字符串
     */
    public static function decrypt($cipherText, $key, $iv, $option = OPENSSL_RAW_DATA, $method = null)
    {
        self::validateKey($key);
        self::validateIv($iv);

        return openssl_decrypt($cipherText, $method ? $method : self::getMode($key), $key, $option, $iv);
    }

    /**
     * 根据 key 的长度选择密码学方式
     *
     * @param string $key
     * @return string
     */
    public static function getMode($key)
    {
        return 'aes-'.(8 * strlen($key)).'-cbc';
    }

    /**
     * 判断 key 的长度是否有效，长度必须是 16, 24, 32 中的一种
     *
     * @param string $key
     * @throws \InvalidArgumentException
     */
    public static function validateKey($key)
    {
        if (!in_array(strlen($key), [16, 24, 32], true)) {
            throw new \InvalidArgumentException(sprintf('Key length must be 16, 24, or 32 bytes; got key len (%s).', strlen($key)));
        }
    }

    /**
     * 判断向量的长度是否有效，必须是16位
     *
     * @param string $iv
     * @throws \InvalidArgumentException
     */
    public static function validateIv($iv)
    {
        if (!empty($iv) && 16 !== strlen($iv)) {
            throw new \InvalidArgumentException('IV length must be 16 bytes.');
        }
    }
}
