package ckcs.classes;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignedObject;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Security {
    //Odd way of creating a trusted authority for authentication, somewhat like CA
    //except using asymmetric keys of a trusted third-party for signatures
    //public key of Player and House are encrypted with TrustedPrivate,
    //Player and House both have TrustedPublic and uses it as an authenticator 
    //(Player/House are authenticated by Trusted third-party, this is shown by their public keys being encrypted
    //by the TrustedPrivate.... also means the respective private key HAS NOT been compromised
    //Then they will both enter the ECDHKeyAgreement and obtain Session Keys
    private volatile static PrivateKey TrustedPrivate;
    private volatile static PublicKey TrustedPublic;
        
    private static void generateTrustedKeyPair() {
        KeyPair keyPair = generateKeyPair();
        TrustedPrivate = keyPair.getPrivate();
        TrustedPublic = keyPair.getPublic();   
    }
    
    public synchronized static SignedObject obtainTrustedSigned(Serializable object) {
        try {
            if (TrustedPrivate == null) {
                generateTrustedKeyPair();
            }
            Signature signature = Signature.getInstance("SHA1withRSA");
            return new SignedObject(object, TrustedPrivate, signature);            
        } catch (NoSuchAlgorithmException | IOException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public static boolean verifyTrustedSigned(SignedObject signed) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            return signed.verify(TrustedPublic, signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;        
    }
    
    public static byte[] RSAEncrypt(final Key key, byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public static byte[] RSADecrypt(final Key key, byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            return keyGen.genKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static byte[] hashFunction(final byte[] input) {
        //returns a 256-bit hash using SHA-256 algo
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(input);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static SecretKey ECDHKeyAgreement(final ObjectInputStream in, final ObjectOutputStream out,
            final PublicKey otherPub, final PrivateKey privKey) {
            //is a BLOCKING function, two users must both confirm to begin before calling this function
            //must be called on both ends after confirmations received
            //include some sort of authentication between users, such as ID, Nonces, Certificates? -- prevent man-in-the-middle/replays
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
            keyPairGen.initialize(128);
            KeyPair keyPair = keyPairGen.genKeyPair();
            byte[] ourPubKeyBytes = keyPair.getPublic().getEncoded();
            byte[] buffer = RSAEncrypt(otherPub, ourPubKeyBytes);
            int length = buffer.length;
            out.writeInt(length);
            out.write(buffer);
            out.flush();
            
            length = in.readInt();
            buffer = new byte[length];
            in.readFully(buffer);
            byte[] otherPubKeyBytes = RSADecrypt(privKey, buffer);
            PublicKey otherPubKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(otherPubKeyBytes));
            
            KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
            keyAgree.init(keyPair.getPrivate());
            keyAgree.doPhase(otherPubKey, true);
            byte[] sharedKeyBytes = keyAgree.generateSecret();
            
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            List<ByteBuffer> pubKeyBytes = Arrays.asList(ByteBuffer.wrap(ourPubKeyBytes), ByteBuffer.wrap(otherPubKeyBytes));
            Collections.sort(pubKeyBytes);
            md.update(sharedKeyBytes);
            md.update(pubKeyBytes.get(0));
            md.update(pubKeyBytes.get(1));
            byte[] secretKeyBytes = md.digest();
            
            return new SecretKeySpec(secretKeyBytes, "AES");
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | InvalidKeyException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static byte[] AESDecrypt(final SecretKey key, final byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static byte[] AESEncrypt(final SecretKey key, final byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(input);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static SecretKey generateRandomKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }   
    
    //update key for JOINS
    public static SecretKey updateKey(final SecretKey key) {
        //returns new 256-bit key value using hash of inputted key
        byte[] keyHash = hashFunction(key.getEncoded());
        return new SecretKeySpec(keyHash, "AES");
    }
    
    public static void deleteKey() {
        
    }

    public static SecretKey middleKeyCalculation(final SecretKey groupKey, final String nodeNumber) {
        byte[] keyBytes = groupKey.getEncoded();
        byte[] number = nodeNumber.getBytes(StandardCharsets.UTF_8);
        for(int i = 0, j = 0; i < keyBytes.length; i++, j++) {
            if (j == number.length - 1) {
                j = 0;
            }
            keyBytes[i] = (byte)(keyBytes[i] ^ number[j]);
        }
        return new SecretKeySpec(keyBytes, "AES");
    }
}