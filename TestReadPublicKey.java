package com.softwareag.pgp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
//import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
//import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.bcpg.sig.KeyFlags;


public class TestReadPublicKey {
	
	public static void main(String args[])throws Exception{
		//PGPPublicKeyRingCollection coll = null;
		
		InputStream in = new FileInputStream(new File("D:\\Users\\itt0277\\Desktop\\PGP\\iseft_pubKey.asc"));
        // Get the decoder stream (auto-disarming)
		//InputStream din = PGPUtil.getDecoderStream(in);
		
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection( PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator() );
		//PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));
		System.out.println(pgpPub.size());
		//keyPub = PGPKeyReader.readPublicKey(ringPub, PGPInit.getKeyExchangeAlgorithm("RSA"));
		ArrayList<String> others = new ArrayList<String>();
        PGPPublicKey key = null;
        main: for (Iterator<?> i = pgpPub.getKeyRings(); i.hasNext();) {
            PGPPublicKeyRing ring = (PGPPublicKeyRing) i.next();
            for (Iterator<?> j = ring.getPublicKeys(); j.hasNext();) {
                PGPPublicKey next = (PGPPublicKey) j.next();
                //logger.debug("Found public key: " 
                //        + PGPInit.getKeyExchangeAlgorithm(next.getAlgorithm()));
                System.out.println( "encryptionKey: "+ next.isEncryptionKey());
                System.out.println( "algoritham: "+ next.getAlgorithm());
                if (next.isEncryptionKey()
                        && (next.getAlgorithm() == 16 || 1 == 0)) {
                    key = next;
                    break main;
                } else {
                    others.add(PGPInit.getKeyExchangeAlgorithm(next.getAlgorithm()));
                }
            }
        }
        
        //Encrypt data
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        //PGPEncrypt.encrypt("Test Data", out, key, 
        		//key.getAlgorithm(), true, null);
        
        System.out.println(others.size());
        //System.out.println( "publicKey: "+ key);
        System.out.println( "publicKey: "+ key);
        System.out.println( "keyId: "+ String.valueOf(key.getKeyID()));
        System.out.println( "algorithm: "+ String.valueOf(key.getAlgorithm()));
        System.out.println( "bitStrength: "+ String.valueOf(key.getBitStrength()));
        System.out.println( "isEncryptionKey: "+ String.valueOf(key.isEncryptionKey()));
        System.out.println( "isMasterKey: "+ String.valueOf(key.isMasterKey()));
        System.out.println( "isRevoked: "+ String.valueOf(key.isRevoked()));
		
		
	}

}
