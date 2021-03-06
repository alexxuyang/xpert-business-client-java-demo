package com.mycompany.app;

import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.text.*;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyAgreement;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import io.javalin.Javalin;
import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
    private static final Logger logger = LoggerFactory.getLogger(App.class);

    class EncryptedMsg {
        private String encrypted;
    
        public EncryptedMsg(){}
    
        public EncryptedMsg(String e) {
            this.encrypted = e;
        }
    
        public String getEncrypted() {
            return this.encrypted;
        }
    
        public void setEncrypted(String e) {
            this.encrypted = e;
        }
    }

    public static byte[] getShareKey() throws Exception {
        // openssl pkcs8 -topk8 -inform PEM -outform DER -in pri_hashkey-hub.pem -out pri_hashkey-hub.der -nocrypt
        byte[] privKeyByteArray1 = Files.readAllBytes(Paths.get("pri_hashkey-hub.der"));
        PKCS8EncodedKeySpec keySpec1 = new PKCS8EncodedKeySpec(privKeyByteArray1);
        KeyFactory keyFactory1 = KeyFactory.getInstance("EC");
        PrivateKey myPrivKey = keyFactory1.generatePrivate(keySpec1);
        logger.info("Algorithm:{}", myPrivKey.getAlgorithm());

        // openssl pkey -pubout -inform pem -outform der -in pri_hashkey-hub.pem -out pub_hashkey-hub.der
        byte[] pubKeyByteArray2 = Files.readAllBytes(Paths.get("pub_gateway.der"));
        X509EncodedKeySpec keySpec2 = new X509EncodedKeySpec(pubKeyByteArray2);
        KeyFactory keyFactory2 = KeyFactory.getInstance("EC");
        PublicKey myPubKey = keyFactory2.generatePublic(keySpec2);
        logger.info("Algorithm:{}", myPubKey.getAlgorithm());

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
        ka.init(myPrivKey);
        ka.doPhase(myPubKey, true);

        byte[] sharedSecret = ka.generateSecret();
        // System.out.println(Base64.getEncoder().encodeToString(sharedSecret));
        return sharedSecret;
    }
    
    public static String decryptMsg(byte[] keys, String msg, String iv_base64) throws Exception {
        byte[] iv = Base64.getDecoder().decode(iv_base64);
        byte[] encrypted_msg = Base64.getDecoder().decode(msg);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keys, "AES"), new IvParameterSpec(iv));
        
        return new String(cipher.doFinal(encrypted_msg));
    }

    public static byte[] encryptMsg(byte[] keys, String msg, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keys, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(msg.getBytes());
    }

    public static void main(String[] args) throws Exception {
        byte[] keys = getShareKey();

        Javalin app = Javalin.create().start(8080);

        app.post("/pong", ctx -> {
            ctx.headerMap().forEach((k,v) -> System.out.printf("%s:%s\n", k, v));
            var iv_base64 = ctx.header("X-Encrypt-Iv");
            var user_id_base64 = ctx.header("X-User-ID");
            
            logger.info("user id base64:{}", user_id_base64);
            logger.info("request body:{}", ctx.body());
            
            Gson g = new Gson();  
            EncryptedMsg msg = g.fromJson(ctx.body(), EncryptedMsg.class);

            logger.info("in_msg_encrypted:{}", msg.getEncrypted());
            String in_msg = decryptMsg(keys, msg.getEncrypted(), iv_base64);
            logger.info("in_msg_dcrypted:{}", in_msg);

            Random random = new Random();
            byte[] iv = new byte[16];
            random.nextBytes(iv);

            String tss = new SimpleDateFormat("dd/MM/yyyy_HH:mm:ss").format(Calendar.getInstance().getTime());
            String out_msg_unencrypted;

            if (user_id_base64 == null) {
                out_msg_unencrypted = String.format("{\"kaka\":\"hahaha\",\"ts\":\"%s\"}", tss);
            } else {
                var user_id = Base64.getDecoder().decode(user_id_base64);
                out_msg_unencrypted = String.format("{\"kaka\":\"hahaha\",\"userID\":\"%s\",\"ts\":\"%s\"}", DatatypeConverter.printHexBinary(user_id), tss);
            }

            logger.info("out_msg_unencrypted:{}", out_msg_unencrypted);            
            byte[] out_msg_encrypted = encryptMsg(keys, out_msg_unencrypted, iv);

            String out_iv_base64 = new String(Base64.getEncoder().encode(iv));
            logger.info("out_iv_base64:{}", out_iv_base64);
            String out_msg_base64 = new String(Base64.getEncoder().encode(out_msg_encrypted));
            logger.info("out_msg_base64:{}", out_msg_base64);
            String result = String.format("{\"encrypted\":\"%s\",\"iv\":\"%s\"}", out_msg_base64, out_iv_base64);

            logger.info("out_msg_result:{}", result);

            ctx.header("X-Encrypted", "true");

            ctx.result(result);
        });

        app.get("/ping", ctx -> {
            ctx.result("Hello World");
        });
    }
}
