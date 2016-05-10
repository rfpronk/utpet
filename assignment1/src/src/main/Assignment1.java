package main;

import java.io.DataOutputStream;
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

// as this is single use code we don't really care about exception handling

public class Assignment1 {

	private String[] studentNumbers = {"s1227874", "s0138746"}; 

    private final static int AES_KEY_SIZE = 128;
    private final static int RSA_KEY_SIZE = 1024;
    
    private final static String MIXNET_HOSTNAME = "pets.ewi.utwente.nl";
    private final static int MIXNET_PORT = 57327;
    private final static int MIXNET_NODE_COUNT=4;

    private final static String[] pubKeys = {
    	"-----BEGIN PUBLIC KEY-----" + '\n' + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC12FPfdepBrzZc9oYrAQMutj/YDSHbVc+6kYMG2igq5aShYDkHUUa63l/u4D6w0d7FXCVvFShDKT9vawVJn8Qd1fyRINJrkufYRD4/n0e6JIGQ4FctpMMkNWAJsqWiNdA54dDrHEE210epDXIVI7e+mOVSme4vOmg1Gfqm7vdc5QIDAQAB" + '\n' + "-----END PUBLIC KEY-----",
    	"-----BEGIN PUBLIC KEY-----" + '\n' + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVhJycScH1rIP6p/c6mMxrDmcKUqEWbXUYMdD2HXtl7tdc1giZaCHMLxNL2loC1CFePW4UbHUVkuI3HBoMHuCm6CiXl3/1nvpRglLw9bVJCU4yLn/DgyNYwOQBK25sj1DiG+mXgIvRpV7Rk44/FltMU1oLUmaBHozLAEcT/y5HJQIDAQAB" + '\n' + "-----END PUBLIC KEY-----",
    	"-----BEGIN PUBLIC KEY-----" + '\n' + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWbUMbBFT9KdUYs5d/tWh7qR5ccBneQN6roVqqVKrxArV0UZMjmvDeyW2dJmmnbKaE6+AsicRWmVXzVWjb3cFHqfnXIkKIP+sskpquSkT7MrejL1IvgKQSy5JTp3EWmLs17fAeJF27bxCfPi0b9ccs1rMo1oEdTA+nuetGeXnCsQIDAQAB" + '\n' + "-----END PUBLIC KEY-----",
    	"-----BEGIN PUBLIC KEY-----" + '\n' + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDD4qir1SKdQDZhCNwM1eMIWwYBviWPc9BZtp/PZS08TEt4V9PhFyuGyZ4v/UiA15JIqNUaK51AUwyqhkDHwmB5zZ9VpiR8xs8Ij8dFpi5Pm/aE2gmSnkPwVL5FgzJKJRqtUeX+yusDOyC9fYDaL8f13BgXwkMx3NCZpSNev8KT8QIDAQAB" + '\n' + "-----END PUBLIC KEY-----"
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
    		this.sendMessage("A greeting from " + this.studentNumbers[0] + " & " + this.studentNumbers[1]);
    	} catch (Exception ex) {
    		System.out.println("ohoh! " + ex.getMessage());
    		ex.printStackTrace();
    	}
    }
    
    public void runAssignment3A() {
    	// params for n-1 attack
    	int runs = 10;
    	int threshold = 7;
    	int runPauseTime = 500; // should be large enough to allow victim to send but not so large for two legit messages
    	
    	try {
    		// perform multiple runs so we don't need to time our attack
	    	for (int i=0; i<runs; i++) {
	    		// spam until threshold is almost reaches (n-1)
		    	for (int j=1; j<threshold; j++) {
			    	this.sendMessage("Boo! #" + i + "|" + j);	
		    	}
		    	// give the victim time to send his/her message
		    	Thread.sleep(runPauseTime);
	    	}
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
    
    private byte[] encryptForNode(byte[] input, int targetNode) throws Exception {
    	byte[] pubKey = new byte[4];
    	
    	Security.addProvider(new BouncyCastleProvider());
    	
    	// using a static IV is fine for now
        AlgorithmParameterSpec IVspec = new IvParameterSpec("0123456789ABCDEF".getBytes());

        // encrypt with PKCS7 padding
        Cipher encrypterWithPad = Cipher.getInstance("AES/CBC/PKCS7PADDING", "BC");
        SecretKey secretKey = new SecretKeySpec( this.symKeys[targetNode].getEncoded(), "AES");
        encrypterWithPad.init(Cipher.ENCRYPT_MODE, secretKey, IVspec);
        byte[] encryptedData = encrypterWithPad.doFinal(input);

        System.out.println("Encoded message: " + new String(encryptedData, "UTF-8"));
        
        // combine pubKey and encrypted message
        byte[] combined = new byte[encryptedData.length + pubKey.length];
        System.arraycopy(encryptedData,0,combined,0,encryptedData.length);
        System.arraycopy(pubKey,0,combined,encryptedData.length,pubKey.length);
        
        return combined;
    }

    private void sendMessage(String msg) throws Exception{
    	System.out.println("Sending message: " + msg);
    	
    	// first encrypt message, start with plain input message
    	byte[] encryptedData = msg.getBytes();
    	// encrypt for all nodes, starting with last one
    	for (int i=MIXNET_NODE_COUNT-1; i>=0; i--) {
    		encryptedData = this.encryptForNode(encryptedData, i);
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
        outputStream.write(encryptedData);
        clientSocket.close();
        
        System.out.println("Finished sending");
    }
 
}
