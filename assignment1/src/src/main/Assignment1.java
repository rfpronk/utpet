package main;

import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.StringReader;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;

// as this is single use code we don't really care about exception handling

public class Assignment1 {

	private String[] studentNumbers = {"s1227874", "s0138746"}; 

    private final static int AES_KEY_SIZE = 128;
    private final static int RSA_KEY_SIZE = 1024;
    
    private final static String MIXNET_HOSTNAME = "pets.ewi.utwente.nl";
    private final static int MIXNET_PORT = 57327;
    private final static int MIXNET_NODE_COUNT=4;

    private final static String[] pubKeys = {
    	"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC12FPfdepBrzZc9oYrAQMutj/YDSHbVc+6kYMG2igq5aShYDkHUUa63l/u4D6w0d7FXCVvFShDKT9vawVJn8Qd1fyRINJrkufYRD4/n0e6JIGQ4FctpMMkNWAJsqWiNdA54dDrHEE210epDXIVI7e+mOVSme4vOmg1Gfqm7vdc5QIDAQAB-----END PUBLIC KEY-----",
    	"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVhJycScH1rIP6p/c6mMxrDmcKUqEWbXUYMdD2HXtl7tdc1giZaCHMLxNL2loC1CFePW4UbHUVkuI3HBoMHuCm6CiXl3/1nvpRglLw9bVJCU4yLn/DgyNYwOQBK25sj1DiG+mXgIvRpV7Rk44/FltMU1oLUmaBHozLAEcT/y5HJQIDAQAB-----END PUBLIC KEY-----",
    	"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWbUMbBFT9KdUYs5d/tWh7qR5ccBneQN6roVqqVKrxArV0UZMjmvDeyW2dJmmnbKaE6+AsicRWmVXzVWjb3cFHqfnXIkKIP+sskpquSkT7MrejL1IvgKQSy5JTp3EWmLs17fAeJF27bxCfPi0b9ccs1rMo1oEdTA+nuetGeXnCsQIDAQAB-----END PUBLIC KEY-----",
    	"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDD4qir1SKdQDZhCNwM1eMIWwYBviWPc9BZtp/PZS08TEt4V9PhFyuGyZ4v/UiA15JIqNUaK51AUwyqhkDHwmB5zZ9VpiR8xs8Ij8dFpi5Pm/aE2gmSnkPwVL5FgzJKJRqtUeX+yusDOyC9fYDaL8f13BgXwkMx3NCZpSNev8KT8QIDAQAB-----END PUBLIC KEY-----"
    	};
    private Key[] symKeys = new Key[MIXNET_NODE_COUNT];
    

    public static void main(String args[]) {
    	System.out.println("Starting assignment1");
    	Assignment1 ass1 = new Assignment1();
    	
    	ass1.runAssignment1B();
    }
    
    /**
     * Constructor
     */
    public Assignment1() {
    	this.generateSymKeys();
    }
    
    public void runAssignment1B() {
    	try {
    		this.sendMessage(this.studentNumbers[0] + " & " + this.studentNumbers[1]);
    	} catch (Exception ex) {
    		System.out.println("ohoh! " + ex.getMessage());
    		ex.printStackTrace();
    	}
    }

    private void generateSymKeys() {
    	try {
    		for (int i=0; i<MIXNET_NODE_COUNT; i++) {
    			this.symKeys[i] = this.generateAESKey();    		}
    	} catch (Exception ex) {
    		System.out.println("Exception generating AES keys: " + ex.getMessage());
    		ex.printStackTrace();
    	}
    }

    private Key generateAESKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	KeyGenerator KeyGen = KeyGenerator.getInstance("AES", "BC");
    	KeyGen.init(Assignment1.AES_KEY_SIZE);
    	Key key = KeyGen.generateKey();
        return key;
    }
    
    private String encryptForNode(String input, int targetNode) throws Exception {
    	String pubKey = "";
    	String encodedMessage;
    	
    	Security.addProvider(new BouncyCastleProvider());
    	
    	// using a static IV is fine for now
        AlgorithmParameterSpec IVspec = new IvParameterSpec("0123456789ABCDEF".getBytes());

        // encrypt with PKCS7 padding
        Cipher encrypterWithPad = Cipher.getInstance("AES/CBC/PKCS7PADDING", "BC");
        SecretKey secretKey = new SecretKeySpec( this.symKeys[targetNode].getEncoded(), "AES");
        encrypterWithPad.init(Cipher.ENCRYPT_MODE, secretKey, IVspec);
        byte[] encryptedData = encrypterWithPad.doFinal(input.getBytes());
        encodedMessage = new String(encryptedData);

        System.out.println("Encoded message: " + encodedMessage);
        
        // encrypt with 1024-bit RSA - optimal Asymmetric Encryption Padding (OAEP) (PKCS1-OAEP)
        Cipher rsawPad = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        StringReader strReader = new StringReader(pubKeys[targetNode]);
        PemReader reader = new PemReader(strReader);
        System.out.println(reader.readPemObject());
        
        return pubKey + encodedMessage;
    }

    private void sendMessage(String msg) throws Exception{
    	System.out.println("Sending message: " + msg);
    	
    	// first encrypt message
    	String result = "";
    	// encrypt for all nodes, starting with last one
    	for (int i=MIXNET_NODE_COUNT-1; i>=0; i--) {
    		result = this.encryptForNode(result, i);
    	}
    	
    	// calculate message length as four byte unsigned big endian
    	ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(msg.length());
        buffer.flip();
        byte[] lengthPreField = buffer.array();
        
        // send message to first mixnet node
        Socket clientSocket = new Socket(Assignment1.MIXNET_HOSTNAME, Assignment1.MIXNET_PORT);
        DataOutputStream outputStream = new DataOutputStream(clientSocket.getOutputStream());
        outputStream.write(lengthPreField);
        outputStream.writeBytes(result);
        clientSocket.close();
        
        System.out.println("Finished sending");
    }
 

}
