import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Client {

    public Client() throws NoSuchAlgorithmException {
        //CONVERTIR TOUS LES STRING EN CHAR
        Scanner sc = new Scanner(System.in);
        String mail;
        String PWD;

        int ansMail;

        //Generation of onTheFly keys
        PublicKey publicKey;
        PrivateKey privateKey;

        KeyPairGenerator PrivkeyGen;

        PrivkeyGen = KeyPairGenerator.getInstance("RSA");
        PrivkeyGen.initialize(4096);
        KeyPair pair = PrivkeyGen.generateKeyPair();

        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        System.out.println("Assymetric keys generated !");

        do{

            Pattern email = Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);
            Matcher matcher ;

            do {
                System.out.println("Please enter your credentials");
                System.out.println("Mail :");
                mail = sc.next();
                matcher = email.matcher(mail);
                if(!matcher.matches()){
                    System.out.println("Please enter a valid mail address ! [_@_._]");
                }
                sc.reset();
            }while (!matcher.matches());

            System.out.println("Password : ");
            //saltedHash
            PWD = sc.next();
            sc.reset();

            Socket socket2 = null;
            try {
                socket2 = new Socket("192.168.56.1", 9000);
                ObjectOutputStream oout=new ObjectOutputStream(socket2.getOutputStream());
                ObjectInputStream iin = new ObjectInputStream(socket2.getInputStream());


                //Send client Hello !
                String hello = "Client Hello";
                //MESSAGE 1
                oout.writeObject(hello+":"+sign(hello , privateKey));
                //MESSAGE 2
                oout.writeObject(publicKey);
                //oout.writeObject( sign(hello , privateKey));

                //Verify certificate !
                //MESSAGE 3
                X509Certificate cert = (X509Certificate)iin.readObject();
                if(!cert.getIssuerDN().getName().equals("EMAILADDRESS=alphatangototo789@gmail.com, CN=SSD, OU=SSD, O=Crochez ssd, L=Bruxelles, ST=Bruxelles, C=BE")){
                    throw  new CertificateException();
                }
                if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                    cert.verify(cert.getPublicKey());
                    System.out.println("Server is : " + cert.getSubjectX500Principal());
                }

                //System.out.println(cert.getPublicKey());

                //MESSAGE 4
                //Get encrypted AES key
                String signedEncAESKey = (String)iin.readObject();
                String encAESKey = signedEncAESKey.split("_")[0];
                String signature = signedEncAESKey.split("_")[1];

                //Check signature
                if(!verify(encAESKey , signature , cert.getPublicKey())){
                    throw new Exception("Not good signature !");
                }
                //Check date
                if(!checkDates(encAESKey.split(":")[1])){
                    throw new Exception("Not valid date !");
                }

                //System.out.println(encAESKey.split(":")[0]);
                //Decipher AES key with RSA !
                Cipher cipher2c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher2c.init(Cipher.DECRYPT_MODE, privateKey);
                SecretKeySpec AESKey = new SecretKeySpec(cipher2c.doFinal(Base64.getDecoder().decode(encAESKey.split(":")[0])), "AES");

                //Send client secure handshake
                String messageToSend = prepareSend("Client Secure Handshake",AESKey , privateKey);
                //MESSAGE 6
                oout.writeObject(messageToSend);

                //Receive Server secure handshake
                //MESSAGE 8
                String signedEncString = (String)iin.readObject();
                String messageReceived = prepareReceive(signedEncString , AESKey , cert.getPublicKey());
                System.out.println(messageReceived);

                //Send user credentials
                String messageToSend2 = prepareSend(mail+"//"+PWD,AESKey , privateKey);
                //MESSAGE 9
                oout.writeObject(messageToSend2);

                //Erase pwd
                PWD=null;
                System.gc();

                //Server answer on connection request !
                //MESSAGE 10
                String signedEncString10 = (String)iin.readObject();
                String messageReceived10 = prepareReceive(signedEncString10 , AESKey , cert.getPublicKey());

                if(messageReceived10.equals(mail+" as good credentials !")){

                    System.out.println(messageReceived10);
                    System.out.println("We send you a mail to email your e-mail !");

                    do{
                        System.out.println("Enter secret code sends to email : ");
                        ansMail = sc.nextInt();
                        sc.reset();

                        //Send user code
                        String messageToSend3 = prepareSend(""+ansMail,AESKey , privateKey);
                        //MESSAGE 11
                        oout.writeObject(messageToSend3);

                        //Receiver server responce for the 2-step
                        //MESSAGE 12
                        String answer = (String)iin.readObject();
                        String messageReceived11 = prepareReceive(answer , AESKey , cert.getPublicKey());
                        String[] splittedAnswer = messageReceived11.split(":");

                        String result = splittedAnswer[0] ;
                        String sessionToken = splittedAnswer[1] ;

                        if(result.equals("MATCH")){
                            //System.out.println("MATCH");
                            //System.out.println(sessionToken);

                            // HERE BEGIN ACTIONS !
                            if(sessionToken.contains("ADMIN") || sessionToken.contains("TEACHER")) {

                                do {//Menu 1
                                    System.out.println("\nWhat do you want to do ?");
                                    System.out.println("\n1. Read");
                                    System.out.println("\n2. Write");
                                    System.out.println("\n3. Exit\n");
                                    int choixe = sc.nextInt();

                                    switch (choixe) {
                                        case 1:
                                            System.out.println("Which student ? ");
                                            String student = sc.next();

                                            //Send user action
                                            String messageToSend4 = prepareSend(sessionToken+":READ:" + student,AESKey , privateKey);
                                            //MESSAGE 13
                                            oout.writeObject(messageToSend4);

                                            //Receive server response !
                                            //MESSAGE 14
                                            String reponse = (String) iin.readObject();
                                            String messageReceived14 = prepareReceive(reponse , AESKey , cert.getPublicKey());

                                            System.out.println(messageReceived14);
                                            break;
                                        case 2:

                                            System.out.println("Which student");
                                            String B = sc.next();

                                            System.out.println("Which course");
                                            String C = sc.next();

                                            System.out.println("Which grade");
                                            float D = sc.nextFloat();

                                            //oout.writeObject(sessionToken+":WRITE" + ":" + B + ":" + C + ":" + D);
                                            //Send user action
                                            String messageToSend5 = prepareSend(sessionToken+":WRITE" + ":" + B + ":" + C + ":" + D,AESKey , privateKey);
                                            //MESSAGE 13
                                            oout.writeObject(messageToSend5);

                                            //Receive server response !
                                            //MESSAGE 14
                                            String reponse2 = (String) iin.readObject();
                                            String messageReceived15 = prepareReceive(reponse2 , AESKey , cert.getPublicKey());

                                            //String reponse3 = (String) iin.readObject();
                                            System.out.println(messageReceived15);

                                            break;
                                        case 3:
                                            System.exit(0);
                                            break;
                                        default:
                                            break;
                                    }
                                } while (true);
                            }else if(sessionToken.contains("STUDENT")){
                                do {//Menu 2
                                    System.out.println("\n\nWhat do you want to ?");
                                    System.out.println("\n1. Read");
                                    System.out.println("\n2. Exit");

                                    int choixe = sc.nextInt();

                                    switch (choixe) {
                                        case 1:

                                            //Send request !
                                            String messageToSend5 = prepareSend(sessionToken+":READ" ,AESKey , privateKey);
                                            //MESSAGE 13
                                            oout.writeObject(messageToSend5);

                                            //Receive answer !
                                            //MESSAGE 14
                                            String reponse2 = (String) iin.readObject();
                                            String messageReceived15 = prepareReceive(reponse2 , AESKey , cert.getPublicKey());

                                            System.out.println(messageReceived15);
                                            break;
                                        case 2:
                                            System.exit(0);
                                            break;
                                        default:
                                            break;
                                    }
                                } while (true);
                            }

                        }else{
                            System.out.println("NOT MATCH");
                        }

                    }while(true);

                }else{
                    System.out.println(messageReceived10);
                }

            } catch (Exception e) {
                System.out.println("There were an error with your client , please contact an admin and send him this error : "+e);
            }
        }while (1==1);
    }

    private String prepareSend(String data, SecretKeySpec AESKey, PrivateKey privateKey) throws Exception {

        SecureRandom random = new SecureRandom();
        byte[] ivSpec0 =  new byte[16];
        random.nextBytes(ivSpec0);
        String message5 = encryptData(data,AESKey,new IvParameterSpec(ivSpec0));
        String messageToSend = Base64.getEncoder().encodeToString(ivSpec0)+":"+timeMessage(message5);

        return messageToSend+"_"+sign(messageToSend , privateKey);
    }
    private String prepareReceive(String signedEncString, SecretKeySpec AESKey, PublicKey publicKey) throws Exception {

        String encMessage = signedEncString.split("_")[0];
        String signature2 = signedEncString.split("_")[1];

        //Check signature
        if(!verify(encMessage , signature2 , publicKey)){
            throw new Exception("Not good signature !");
        }
        //Check date
        if(!checkDates(encMessage.split(":")[2])){
            throw new Exception("Not good date !");
        }
        //Decipher message
        String decryptedMessage = decryptData(encMessage.split(":")[1] , AESKey ,new IvParameterSpec(Base64.getDecoder().decode(encMessage.split(":")[0])));
        if(decryptedMessage.equals("Connection Reset !")){
            throw new Exception("Connection Reset");
        }

        return decryptedMessage;
    }

    private boolean checkDates(String date){

        String[] splitted = date.split("-");

        Calendar construct = Calendar.getInstance();

        construct.set(Calendar.YEAR , Integer.parseInt(splitted[0]));
        construct.set(Calendar.MONTH , Integer.parseInt(splitted[1])-1);
        construct.set(Calendar.DAY_OF_MONTH , Integer.parseInt(splitted[2]));

        construct.set(Calendar.HOUR , Integer.parseInt(splitted[3]));
        construct.set(Calendar.MINUTE , Integer.parseInt(splitted[4]));
        construct.set(Calendar.SECOND , Integer.parseInt(splitted[5]));

        construct.add(Calendar.SECOND, 360);
        Date toCompareplus5 = construct.getTime();
        Date currentDate = new Date();

        if(toCompareplus5.after(currentDate)){
            return true;
        }

        return false;
    }

    private String timeMessage(String message){
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd-hh-mm-ss");
        Date currentDate = new Date();
        return message+":"+df.format(currentDate);
    }

    //Based on https://www.developpez.net/forums/d1803792/java/general-java/signature-verification-rsa-java/
    private static String sign(String plainText, PrivateKey privateKey) throws Exception {

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }
    //Based on https://www.developpez.net/forums/d1803792/java/general-java/signature-verification-rsa-java/
    private static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }
    private String encryptData(String data , SecretKey secretKey, IvParameterSpec iv ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipherAlpha = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipherAlpha.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encryptedWithAES = cipherAlpha.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedWithAES);
    }
    private String decryptData(String encData ,SecretKey secretKey, IvParameterSpec iv ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipherBeta = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipherBeta.init(Cipher.DECRYPT_MODE, secretKey ,iv);
        byte[] original = cipherBeta.doFinal(Base64.getDecoder().decode(encData));
        return new String(original);
    }
    //Method based on https://stackoverflow.com/questions/5531455/how-to-hash-some-string-with-sha256-in-java
    public static String sha256(String base) {
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(base.getBytes("UTF-8"));
            StringBuffer hexString = new StringBuffer();

            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if(hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch(Exception ex){
            throw new RuntimeException(ex);
        }
    }
}