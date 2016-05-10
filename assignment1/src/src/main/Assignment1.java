package main;

import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class Assignment1 {


    private final static int AES_KEY_SIZE = 128;
    private final static int RSA_KEY_SIZE = 1024;

    private final static String pubKeyA = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC12FPfdepBrzZc9oYrAQMutj/YDSHbVc+6kYMG2igq5aShYDkHUUa63l/u4D6w0d7FXCVvFShDKT9vawVJn8Qd1fyRINJrkufYRD4/n0e6JIGQ4FctpMMkNWAJsqWiNdA54dDrHEE210epDXIVI7e+mOVSme4vOmg1Gfqm7vdc5QIDAQAB-----END PUBLIC KEY-----";
    private final static String pubKeyB = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVhJycScH1rIP6p/c6mMxrDmcKUqEWbXUYMdD2HXtl7tdc1giZaCHMLxNL2loC1CFePW4UbHUVkuI3HBoMHuCm6CiXl3/1nvpRglLw9bVJCU4yLn/DgyNYwOQBK25sj1DiG+mXgIvRpV7Rk44/FltMU1oLUmaBHozLAEcT/y5HJQIDAQAB-----END PUBLIC KEY----";
    private final static String pubKeyC = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWbUMbBFT9KdUYs5d/tWh7qR5ccBneQN6roVqqVKrxArV0UZMjmvDeyW2dJmmnbKaE6+AsicRWmVXzVWjb3cFHqfnXIkKIP+sskpquSkT7MrejL1IvgKQSy5JTp3EWmLs17fAeJF27bxCfPi0b9ccs1rMo1oEdTA+nuetGeXnCsQIDAQAB-----END PUBLIC KEY-----";
    private final static String pubKeyD = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDD4qir1SKdQDZhCNwM1eMIWwYBviWPc9BZtp/PZS08TEt4V9PhFyuGyZ4v/UiA15JIqNUaK51AUwyqhkDHwmB5zZ9VpiR8xs8Ij8dFpi5Pm/aE2gmSnkPwVL5FgzJKJRqtUeX+yusDOyC9fYDaL8f13BgXwkMx3NCZpSNev8KT8QIDAQAB-----END PUBLIC KEY-----";

    private SecretKeySpec symKeyA, symKeyB, symKeyC, symKeyCache;

    public static void main(String args[]) {
    	Assignment1 ass1 = new Assignment1();

    }
    
    public Assignment1() {
    	
    }

    private void generateSymKeys() {
        this.symKeyA = this.generateAESKey();
        this.symKeyB = this.generateAESKey();
        this.symKeyC = this.generateAESKey();
        this.symKeyCache = this.generateAESKey();
    }

    private SecretKeySpec generateAESKey() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        return key;
    }

    public void sendMessage(String msg) {
    	
    }


}
