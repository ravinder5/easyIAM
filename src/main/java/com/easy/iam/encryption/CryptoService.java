package com.easy.iam.encryption;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Service
public class CryptoService {

    @Value("${public-key}")
    private String publicKey;
    @Value("${private-key}")
    private String privateKey;

    public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        try {
            /* Read the private key bytes */
            Path path = Paths.get("test.pub");
            byte[] bytes = Files.readAllBytes(path);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            getCryptoKeys();
            /* Read the private key bytes */
            Path path = Paths.get("test.key");
            byte[] bytes = Files.readAllBytes(path);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }
    }

    public PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        try {
            /* Read the private key bytes */
            Path path = Paths.get("test.key");
            byte[] bytes = Files.readAllBytes(path);

            /* Generate private key. */
            PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(priKeySpec);
        } catch (Exception e) {
            getCryptoKeys();
            /* Read the private key bytes */
            Path path = Paths.get("test.key");
            byte[] bytes = Files.readAllBytes(path);

            /* Generate private key. */
            PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(priKeySpec);
        }
    }

    public void getCryptoKeys() throws NoSuchAlgorithmException, IOException {
        KeyPair keyPair = generateRSAKeyPair();
        OutputStream out;
        String outFile = "test";
        out = new FileOutputStream(outFile + ".key");
        out.write(keyPair.getPrivate().getEncoded());
        out.close();

        out = new FileOutputStream(outFile + ".pub");
        out.write(keyPair.getPublic().getEncoded());
        out.close();
    }

    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
