package main;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.Socket;
import java.net.URL;
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

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

// as this is single use code we don't really care about exception handling

public class Assignment1 {

	 // --------- vars and data ---------------
	
	private String[] studentNumbers = {"s1227874", "s0138746"}; 

    private final static int AES_KEY_SIZE = 128;
    private final static int RSA_KEY_SIZE = 1024;
    
    private final static String MIXNET_HOSTNAME = "pets.ewi.utwente.nl";
    private final static int MIXNET_PORT = 53069;
    private final static int MIXNET_NODE_COUNT=4; // we count the cache node as mixnet node
    private final static String MIXNET_RECEIVE_LOG_URL = "http://pets.ewi.utwente.nl:57327/log/cache";
    private final static String MIXNET_OTHERS_LOG_URL = "http://pets.ewi.utwente.nl:57327/log/clients";
    
    private final static String MIXNET_RESET_URL = "http://pets.ewi.utwente.nl:57327/cmd/reset";
    private final static String MIXNET_START_URL = "http://pets.ewi.utwente.nl:57327/cmd/mix";


    private final static String[] pubKeys = {
    	"-----BEGIN PUBLIC KEY-----" + '\n' + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC12FPfdepBrzZc9oYrAQMutj/YDSHbVc+6kYMG2igq5aShYDkHUUa63l/u4D6w0d7FXCVvFShDKT9vawVJn8Qd1fyRINJrkufYRD4/n0e6JIGQ4FctpMMkNWAJsqWiNdA54dDrHEE210epDXIVI7e+mOVSme4vOmg1Gfqm7vdc5QIDAQAB" + '\n' + "-----END PUBLIC KEY-----",
    	"-----BEGIN PUBLIC KEY-----" + '\n' + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVhJycScH1rIP6p/c6mMxrDmcKUqEWbXUYMdD2HXtl7tdc1giZaCHMLxNL2loC1CFePW4UbHUVkuI3HBoMHuCm6CiXl3/1nvpRglLw9bVJCU4yLn/DgyNYwOQBK25sj1DiG+mXgIvRpV7Rk44/FltMU1oLUmaBHozLAEcT/y5HJQIDAQAB" + '\n' + "-----END PUBLIC KEY-----",
    	"-----BEGIN PUBLIC KEY-----" + '\n' + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWbUMbBFT9KdUYs5d/tWh7qR5ccBneQN6roVqqVKrxArV0UZMjmvDeyW2dJmmnbKaE6+AsicRWmVXzVWjb3cFHqfnXIkKIP+sskpquSkT7MrejL1IvgKQSy5JTp3EWmLs17fAeJF27bxCfPi0b9ccs1rMo1oEdTA+nuetGeXnCsQIDAQAB" + '\n' + "-----END PUBLIC KEY-----",
    	"-----BEGIN PUBLIC KEY-----" + '\n' + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDD4qir1SKdQDZhCNwM1eMIWwYBviWPc9BZtp/PZS08TEt4V9PhFyuGyZ4v/UiA15JIqNUaK51AUwyqhkDHwmB5zZ9VpiR8xs8Ij8dFpi5Pm/aE2gmSnkPwVL5FgzJKJRqtUeX+yusDOyC9fYDaL8f13BgXwkMx3NCZpSNev8KT8QIDAQAB" + '\n' + "-----END PUBLIC KEY-----"
    	};
    private Key[] symKeys = new Key[MIXNET_NODE_COUNT];    
    
    // --------- basic class functions ---------------
    
    public static void main(String args[]) {
    	System.out.println("Starting PET assignment 1");
    	Assignment1 ass1 = new Assignment1();
    	
    	//ass1.runAssignment1B();
    	//ass1.runAssignment2A(36);
    	
    	// run multiple times to be sure
    	int iterations=5;
    	String badUsers[] = new String[iterations];
    	for (int i=0; i<iterations; i++) {
    		badUsers[i] = ass1.runAssignment3A();
    	}
    	System.out.print("Found bad users: ");
    	for (int i=0; i<iterations; i++) {
    		System.out.print(badUsers[i] + " | ");
    	}
    	System.out.println("");
    	
    }
    
    /**
     * Constructor
     */
    public Assignment1() {
    	this.generateSymKeys();
    }
    
    // --------- assignment specific functions ---------------
    
    public void runAssignment1B() {
    	try {
    		this.startMixnet(1);
    		this.sendMessage("TIM\tA greeting from " + this.studentNumbers[0] + " & " + this.studentNumbers[1]);
    	} catch (Exception ex) {
    		System.out.println("ohoh! " + ex.getMessage());
    		ex.printStackTrace();
    	}
    }
    
    public void runAssignment2A(int runs) {
    	try {
    		this.startMixnet(2);
	    	for (int i=0; i<runs; i++) {		    	
			    this.sendMessage("I am number " + i);	
	    	}
    	} catch (Exception ex) {
    		System.out.println("ohoh! " + ex.getMessage());
    		ex.printStackTrace();
    	}
    }
    
    public String runAssignment3A() {
    	// some working vars
    	String badUser = "";
    	int cnt = 0;
    	String prevSender = "";
    	int lastOutput = 0;
    	boolean go = true;    	
    	boolean hunt = false;
    	
    	// settings
    	String spamMessage = "Boo!";
    	String wantedMessage = "Tim";
    	int fullFlushThreshold = 6; // found using method of 2a
    	
    	// we want to monitor senders. after someone sends we want an isolated output of the single message to Tim and aside that only our own messages.
    	try {
    		this.startMixnet(3);
    		
    		// prefill mixer buckets
			for (int j=0; j<fullFlushThreshold/2; j++) {
				this.sendMessage(spamMessage + " #" + cnt++);	
			}
    		
    		// keep running until we have our result then stop immediately
	    	while (go) {
	    		// get client log
	    		String senders = this.readHTTPPage(MIXNET_OTHERS_LOG_URL);
	    		String[] senderLines = senders.split("\n");
	    		String lastSender = senderLines[senderLines.length - 1];
	    		
    			// something new send?
    			if (lastSender.equals(prevSender)) {
    				// nothing new, hunting?
    				if (hunt) {
    					String output = this.readHTTPPage(MIXNET_RECEIVE_LOG_URL);
    					String[] outputLines = output.split("\n");
	    				// check if output since last send message only contains a single wanted message aside our own messages
	    	    		int notOurs = 0;
	    	    		boolean found = false;
	    	    		// search from last output position before new message was send
	    		    	int start = lastOutput-1;
	    		    	if (start > 0) {
		    				// we want a full flush with only our messages after the wanted message, so no confusing mixing is done in between
	    		    		for (int i=start; i<outputLines.length; i++) {
	    		    			if (outputLines[i].contains(wantedMessage)) {
	    		    				found = true;
	    		    			} else {
	    		    				if (!outputLines[i].contains(spamMessage)) {
	    		    					notOurs++;
	    		    					//System.out.println("Found a different message from user " + lastSender.substring(29, lastSender.indexOf(" ", 29)) + ": " + outputLines[i]);
	    		    				}
	    		    			}
	    		    		}
	    	    		}
	    		    	lastOutput = outputLines.length;
	    		    	if (outputLines.length - start > fullFlushThreshold) {
	    		    		hunt = false;
	    		    		System.out.println("Stopping hunt");
	    		    	}
	    		    	
	    		    	if (found && notOurs == 0) {
	    	    			// message is found exclusively, lets pick the last sender from the log
	    	    			badUser = lastSender.substring(29, lastSender.indexOf(" ", 29));
	    	    			System.out.println("Found the wanted message from sender: " + badUser);
	    	    			// got him/her! so we can stop now
	    	    			go = false;
	    	    		} else if (found) {
	    		    		System.out.println("Found wanted message but not exclusive " + notOurs + " other messages in output batch");
	    	    		}
    				}
    			} else {
    				// yes a new message, time to flush!
    				
    				// start hunting, save last output position
    				hunt = true;
    				
    				String output = this.readHTTPPage(MIXNET_RECEIVE_LOG_URL);
					String[] outputLines = output.split("\n");
					lastOutput = outputLines.length;
					
					System.out.println("New sender " + lastSender);
					// flush to full threshold minus 1 (n-1 attack)
    				for (int j=0; j<fullFlushThreshold-1; j++) {
	    				this.sendMessage(spamMessage + " #" + cnt++);	
	    			}
    				prevSender = lastSender;		
    			}		
	    	}
    	} catch (Exception ex) {
    		System.out.println("ohoh! " + ex.getMessage());
    		ex.printStackTrace();
    	}
    	return badUser;
    }
    
    // --------- mixnet functions ---------------

    private void generateSymKeys() {
    	try {
    		for (int i=0; i<MIXNET_NODE_COUNT; i++) {
    			this.symKeys[i] = this.generateAESKey();
    		}
    	} catch (Exception ex) {
    		System.out.println("Exception generating AES keys: " + ex.getMessage());
    		ex.printStackTrace();
    	}
    }

    private Key generateAESKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	KeyGenerator KeyGen = KeyGenerator.getInstance("AES", "BC");
    	KeyGen.init(Assignment1.AES_KEY_SIZE);
    	return KeyGen.generateKey();
    }
    
    private byte[] encryptForNode(byte[] inputPayload, int targetNode) throws Exception {
    	// --- first we encrypt our payload
    	Security.addProvider(new BouncyCastleProvider());
    	
    	// using a static and shared IV is not very secure but fine for this assignment
    	byte[] ivBytes = "0123456789ABCDEF".getBytes();
        AlgorithmParameterSpec IVspec = new IvParameterSpec(ivBytes);

        // encrypt with PKCS7 padding
        Cipher encrypterWithPad = Cipher.getInstance("AES/CBC/PKCS7PADDING", "BC");
        SecretKey secretKey = new SecretKeySpec( this.symKeys[targetNode].getEncoded(), "AES");
        encrypterWithPad.init(Cipher.ENCRYPT_MODE, secretKey, IVspec);
        byte[] encryptedData = encrypterWithPad.doFinal(inputPayload);
        //System.out.println("AES encoded message: " + new String(encryptedData, "UTF-8"));  
        
        // --- Second we encrypt our symmetric key with the asymetric key of the target
        // encryption with 1024-bit RSA - optimal Asymmetric Encryption Padding (OAEP) (PKCS1-OAEP)
        
        // get key from PEM input
        PemReader pemReader = new PemReader(new StringReader(pubKeys[targetNode]));
        PemObject pemObject = pemReader.readPemObject();
        byte[] keyContent = pemObject.getContent();
        AsymmetricKeyParameter asymPubKey = PublicKeyFactory.createKey(keyContent);
        pemReader.close();
        
        // add OAEP encoding
        AsymmetricBlockCipher asymBlockCipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        asymBlockCipher.init(true, asymPubKey);
        
        // combine symmetric encryption key and IV for RSA encryption
        byte[] rsaInput = combineByteArray(this.symKeys[targetNode].getEncoded(), ivBytes);
        
        // encrypt using RSA
        byte[] rsaOutput = asymBlockCipher.processBlock(rsaInput, 0, rsaInput.length);
        
        // --- Third we combine both parts
        
        // combine pubKey and encrypted message
        return combineByteArray(rsaOutput, encryptedData);
    }

    private void sendMessage(String msg) throws Exception{
    	//System.out.println("Sending message: " + msg);
    	
    	// first encrypt message, start with plain input message
    	byte[] encryptedData = msg.getBytes();
    	// encrypt for all nodes, starting with last one, creating onion
    	for (int i=MIXNET_NODE_COUNT-1; i>=0; i--) {
    		encryptedData = this.encryptForNode(encryptedData, i);
    	}
    	
    	// calculate message length as four byte unsigned big endian
    	ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(encryptedData.length);
        buffer.flip();
        byte[] lengthPreField = buffer.array();
        
        //System.out.println("Message length is " + msg.length());
        //System.out.println("Data length is " + encryptedData.length);

        // send message to first mixnet node
        Socket clientSocket = new Socket(Assignment1.MIXNET_HOSTNAME, Assignment1.MIXNET_PORT);
        DataOutputStream outputStream = new DataOutputStream(clientSocket.getOutputStream());
        outputStream.write(combineByteArray(lengthPreField, encryptedData));
        clientSocket.close();
        
        //System.out.println("Finished sending");
    }

    
    // --------- helper functions ---------------
    
    private byte[] combineByteArray(byte[] a, byte[] b) {
    	byte[] combined = new byte[a.length + b.length];
        System.arraycopy(a, 0, combined, 0, a.length);
        System.arraycopy(b, 0, combined, a.length, b.length);
        return combined;
    }
    
    private String readHTTPPage(String webpage) throws Exception {
    	String result = "";
    	try {
	    	URL URL = new URL(webpage);
	        BufferedReader in = new BufferedReader(new InputStreamReader(URL.openStream()));
	
	        String inputLine;
	        while ((inputLine = in.readLine()) != null) {
	            result += inputLine + '\n';
	        }
	        in.close();
    	} catch (FileNotFoundException ex) {
    		if (webpage.contains("log")) {
    			// probably not ready yet, thats okay
    		} else {
    			throw ex;
    		}
    	}
        return result;
    }
    
    private void startMixnet(int number) throws Exception {
    	System.out.println("Stopping running mixnet if any");
    	this.readHTTPPage(MIXNET_RESET_URL);
    	Thread.sleep(1000);
    	System.out.println("Starting mixnet " + number);
    	this.readHTTPPage(MIXNET_START_URL + number);
    	Thread.sleep(200);
    }
    
}
