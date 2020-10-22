

import com.fortanix.sdkms.jce.provider.SdkmsJCE;
import com.fortanix.sdkms.jce.provider.AlgorithmParameters;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import com.fortanix.sdkms.jce.provider.SdkmsJCE;
import com.fortanix.sdkms.jce.provider.util.ProviderConstants;
import com.fortanix.sdkms.v1.model.CipherMode;
import org.apache.commons.codec.binary.Base64;

public class Sample {


    private static String encrypt(Provider provider, Key key, String plain, String mode, int length) {
        byte[] iv = new byte[length / 8];
        SecureRandom prng = new SecureRandom();
        prng.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance(mode, provider);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] byteCipherText = cipher.doFinal(plain.getBytes());
            String cryptStruct = new Base64().encodeAsString(iv) + ":" + new Base64().encodeAsString(byteCipherText);
            return  cryptStruct;
        } catch (Exception e) {
            System.out.println("Encryption failed: " + e);
            return null;
        }
    }

    public static void createKey(String[] args) throws InterruptedException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, KeyStoreException, IOException, CertificateException {
        SdkmsJCE provider = new SdkmsJCE();
        Security.addProvider(provider);
        String algorithm = AlgorithmParameters.AES;
        String mode = "AES/GCM/NoPadding";
        String padding = ProviderConstants.PKCS5PADDING;
        String encryptData = "Harsha";
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, provider);
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        encrypt(provider,secretKey,encryptData,mode,128);

    }

    public static void main(String[] args) throws InterruptedException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        SdkmsJCE provider = new SdkmsJCE();
        Security.addProvider(provider);
        String algorithm = AlgorithmParameters.AES;
        String mode = "AES/CBC/PKCS5Padding";
        String padding = ProviderConstants.PKCS5PADDING;
        String encryptData = "Harsha";
        String apikey = "";
        KeyStore keyStore = KeyStore.getInstance("SDKMS", provider);
        keyStore.load(null, apikey.toCharArray());
        System.out.println("Successfully logged in to Fortanix SDKMS");
        Key key = keyStore.getKey("aes-128",apikey.toCharArray());
        encrypt(provider, key, encryptData, mode, 128);

    }
}
