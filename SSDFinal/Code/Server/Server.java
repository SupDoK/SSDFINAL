import java.io.*;
import java.security.*;

//NETWORK IMPORT
import java.net.ServerSocket;
import java.net.Socket;

//MAIL IMPORT
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Server {

    private int ivGenerated = 0;
    private String[] ivCache;


    private FileAccessor fa;

    public Server(){
        fa = new FileAccessor();
        ivCache = new String[50];
        try {
            demarrer();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void demarrer() throws IOException {
        ServerSocket ss = new ServerSocket(9000);
        fa.appendLog("INFO","Server Started !");
        System.out.println("Server started and listening !");
        try {

            //Load needed ressources !
            //LOAD certificate !
            CertificateFactory fact = null;
            fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream ("./src/ressources/Certificate.pem");
            final X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
            String keyPath = "./src/ressources/TAMERSSDKey.der";
            File privKeyFile = new File(keyPath);

            //LOAD private key !
            DataInputStream dis = new DataInputStream(new FileInputStream(privKeyFile));
            byte[] privKeyBytes = new byte[(int)privKeyFile.length()];
            dis.read(privKeyBytes);
            dis.close();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
            final RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);

            //Wipe data !
            //cipher2c = null;
            privSpec = null;
            keyFactory= null;
            privKeyBytes = null;
            privKeyFile = null;
            //privKey = null;
            System.gc();


            while(true){

                Socket s = ss.accept();
                // ...

                Thread communication2 = new Thread(() -> {
                    int upThread =10000;

                    try (ObjectOutputStream oout=new ObjectOutputStream(s.getOutputStream());
                         ObjectInputStream iin = new ObjectInputStream(s.getInputStream())) {
                        int nbGenerated;

                        fa.appendLog("INFO","New Client Connection !");
                        //Receive HELLO CLIENT !
                        //MESSAGE 1
                        String signedHelloClient = (String)iin.readObject();
                        //MESSAGE 2
                        PublicKey ClientPublicKey =  (PublicKey)iin.readObject() ;
                        //String signature =  (String)iin.readObject();
                        String helloClient = signedHelloClient.split(":")[0];
                        String signature = signedHelloClient.split(":")[1];

                        if(!helloClient.equals("Client Hello")){
                            //boolean banswer = verify(helloClient , signature , ClientPublicKey);
                            //System.out.println(banswer);
                            if(!verify(helloClient , signature , ClientPublicKey)){
                                //TODO Connection reset !
                                fa.appendLog("ERROR","Client Public Key does not match Signature !");
                                throw new Exception("Not good signature !");
                            }
                        }

                        //Generate AES key !
                        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                        keyGen.init(256); // for example
                        SecretKey secretKey = keyGen.generateKey();

                        //Encrypt AES key with RSA
                        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipher.init(Cipher.ENCRYPT_MODE, ClientPublicKey);
                        byte[] crypteedKey = cipher.doFinal(secretKey.getEncoded());

                        String cryptedkeyString = Base64.getEncoder().encodeToString(crypteedKey);

                        //Send certificate
                        //MESSAGE 3
                        oout.writeObject(cer);
                        // Send encrypted key !
                        //MESSAGE 4
                        String message4 = timeMessage(cryptedkeyString);
                        oout.writeObject(message4+"_"+sign(message4, privKey));

                        //MESSAGE 6
                        String messageFromClient0 = (String)iin.readObject();
                        String receivedMessage = prepareReceive(messageFromClient0,secretKey,ClientPublicKey);
                        System.out.println(receivedMessage);

                        //Send server secure handshake
                        String messageToSends = prepareSend("Server Secure Handshake",secretKey ,privKey );
                        //MESSAGE 8
                        oout.writeObject(messageToSends);

                        //Receive user credentials
                        //MESSAGE 9
                        String messageFromClient1 = (String)iin.readObject();
                        String receivedMessage1 = prepareReceive(messageFromClient1,secretKey,ClientPublicKey);
                        //System.out.println(receivedMessage1);

                        String A = receivedMessage1.split("//")[0];
                        String B = receivedMessage1.split("//")[1];

                        //System.out.println("Je suis "+A+" et mon pwd est : "+B);

                        String status = fa.connect(A,B);

                        B=null;
                        System.gc();

                        if (!status.equals("NOTHING")&&!status.equals("BADCRED")&&!status.equals("LOCKED")){

                            fa.appendLog("SUCCESS_LOGIN",A+" entered good credentials !");
                            //Send connection answer
                            String messageToSends2 = prepareSend(A+" as good credentials !",secretKey ,privKey );
                            //MESSAGE 10
                            oout.writeObject(messageToSends2);

                            nbGenerated = SendMail(A);
                            System.out.println("THIS IS THE CODE IN CASE YOU DID NOT RECEIVE THE MAIL ! : "+nbGenerated);

                            boolean bouboul = true;

                            while (bouboul){

                                //Receive user code
                                //MESSAGE 11
                                String code = (String)iin.readObject();
                                String code0 = prepareReceive(code,secretKey,ClientPublicKey);
                                //System.out.println("CODE RECU : "+code0);

                                if(code0.equals(nbGenerated+"")){

                                    fa.appendLog("SUCCESS_2STEP",A+" entered a good verification code !");

                                    String sentToken = status+"//"+12345;

                                    //Send connection token
                                    String messageToSends3 = prepareSend("MATCH:"+sentToken,secretKey ,privKey );
                                    //MESSAGE 12
                                    oout.writeObject(messageToSends3);

                                    //oout.writeObject("MATCH:"+sentToken);
                                    //System.out.println("TOKEN = "+sentToken);

                                    boolean bulbybool = true;

                                    while (bulbybool){

                                        //MESSAGE 13
                                        String fullAction = (String)iin.readObject();
                                        String message13 = prepareReceive(fullAction,secretKey,ClientPublicKey);
                                        String[] splittedFullAction = message13.split(":");

                                        String token = splittedFullAction[0];
                                        String action = splittedFullAction[1];

                                        //System.out.println(action);
                                        String answer= "Goumed";

                                        if(token.contains("ADMIN")) {
                                            if(action.equals("READ")){

                                                //System.out.println(splittedFullAction[2]);
                                                answer = fa.get(splittedFullAction[2]);

                                                fa.appendLog("ACTION","ADMIN "+A+" did read "+splittedFullAction[2]);
                                            }else if (action.equals("WRITE")){

                                                //System.out.println(splittedFullAction[2]);
                                                //System.out.println(splittedFullAction[3]);
                                                //System.out.println(splittedFullAction[4]);

                                                answer = fa.adminSet(A , splittedFullAction[2],splittedFullAction[3],Float.parseFloat(splittedFullAction[4]));

                                            }else if (action.split(":")[0].equals("EXIT")){
                                                fa.appendLog("CLIENT","ADMIN "+A+" reset connection !");
                                                bulbybool = false;

                                            }
                                        }else if(token.contains("STUDENT")){

                                            if(action.equals("READ")){
                                                //System.out.println(token.split("//")[1]);
                                                answer = fa.get(token.split("//")[1]);

                                                fa.appendLog("ACTION","Client "+A+" did read "+token.split("//")[1]);
                                            }else if (action.split(":")[0].equals("EXIT")){
                                                fa.appendLog("CLIENT","STUDENT "+A+" reset connection !");
                                                bulbybool = false;
                                            }

                                        }else if(token.contains("TEACHER")){

                                            if(action.equals("READ")){

                                                //System.out.println(splittedFullAction[2]);
                                                answer = fa.get(splittedFullAction[2]);
                                                fa.appendLog("ACTION","TEACHER "+A+" did read "+splittedFullAction[2]);

                                            }else if (action.equals("WRITE")){

                                                //System.out.println(splittedFullAction[2]);
                                                //System.out.println(splittedFullAction[3]);
                                                //System.out.println(splittedFullAction[4]);
                                                answer = fa.set(token.split("//")[1],splittedFullAction[2],splittedFullAction[3],Float.parseFloat(splittedFullAction[4]));

                                            }else if (action.split(":")[0].equals("EXIT")){
                                                fa.appendLog("CLIENT","TEACHER "+A+" reset connection !");
                                                bulbybool = false;

                                            }

                                        }

                                        //Send connection token
                                        String messageToSends14 = prepareSend(answer,secretKey ,privKey );
                                        //MESSAGE 14
                                        oout.writeObject(messageToSends14);
                                    }

                                    bouboul= false;

                                }else{

                                    System.out.println("Value of time : "+upThread+"");
                                    fa.appendLog("FAIL_2STEP",A+" entered a bad verification code !");
                                    Thread.sleep(upThread);
                                    upThread *= 2;

                                    //Send error
                                    String messageToSends3 = prepareSend("NOT MATCH",secretKey ,privKey );
                                    //MESSAGE 12bis
                                    oout.writeObject(messageToSends3);

                                    //oout.writeObject("NOT MATCH");
                                }
                            }

                        }else if(status.equals("LOCKED")){
                            //Send connection answer bis
                            String messageToSends2 = prepareSend(A+" account is locked ! ",secretKey ,privKey );
                            fa.appendLog("FAIL_LOGIN",A+" tryed to login while locked !");

                            //MESSAGE 10bis
                            oout.writeObject(messageToSends2);

                        }else if(status.equals("BADCRED")){
                            //Send connection answer bis
                            String messageToSends2 = prepareSend("Password and username does not match !",secretKey ,privKey );
                            fa.appendLog("FAIL_LOGIN",A+" entered a bad password !");

                            //MESSAGE 10bis
                            oout.writeObject(messageToSends2);
                        }else if(status.equals("BROKEN FILE")){
                            //Send connection answer bis
                            String messageToSends2 = prepareSend("File integrity is broken , please contact an admin !",secretKey ,privKey );
                            fa.appendLog("BROKEN_FILE",A+" not cheked because file broke !");

                            //MESSAGE 10bis
                            oout.writeObject(messageToSends2);
                        }else{
                            //Send connection answer bis
                            String messageToSends2 = prepareSend("Password and username does not match !",secretKey ,privKey );
                            fa.appendLog("NO_USER",A+" does not exist !");

                            //MESSAGE 10bis
                            oout.writeObject(messageToSends2);
                        }

                        oout.flush();

                        iin.close();
                        oout.close();
                        s.close();
                    } catch (Exception e) {
                        fa.appendLog("SERVER_ERROR","Error is : "+e);
                        //System.out.println(e);
                    }
                });

                communication2.setDaemon(true);
                communication2.start();

            }

        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            fa.appendLog("SERVER_ERROR","Error is : "+e);
            e.printStackTrace();
        }
    }

    private String prepareSend(String data, SecretKey AESKey, PrivateKey privateKey) throws Exception {

        //TODO Generate random IV
        SecureRandom random = new SecureRandom();
        byte[] ivSpec0 =  new byte[16];

        random.nextBytes(ivSpec0);
        String message5 = encryptData(data,AESKey,new IvParameterSpec(ivSpec0));
        String messageToSend = Base64.getEncoder().encodeToString(ivSpec0)+":"+timeMessage(message5);

        return messageToSend+"_"+sign(messageToSend , privateKey);
    }

    private String prepareReceive(String signedEncString, SecretKey AESKey, PublicKey publicKey) throws Exception {

        String encMessage = signedEncString.split("_")[0];
        String signature2 = signedEncString.split("_")[1];

        boolean banswer0 = verify(encMessage , signature2 , publicKey);
        //System.out.println(banswer0);
        if(!banswer0){
            throw new Exception("Signature NOT OK !");
        }

        //Check date
        boolean ok0 = checkDates(encMessage.split(":")[1] , encMessage.split(":")[2]);
        //System.out.println(ok0);
        if(!ok0){
            throw new Exception("Dates not OK !");
        }

        byte[] iv = Base64.getDecoder().decode(encMessage.split(":")[0]);

        String b64IV = Base64.getEncoder().encodeToString(iv);
        //System.out.println(Base64.getEncoder().encodeToString(iv));

        //check if iv is in the cache
        if(checkIVCache(b64IV)){
            //System.out.println("!!!!!!!!!!!!!!!!!!!REUSED IV !!!!!!!!!!!!!!!!!!!!!!!!!");
            throw new Exception("REUSED IV KEY");
        }

        //stack iv in the cache
        ivCache[ivGenerated] = b64IV;
        ivGenerated++;
        //Decipher message
        String decryptedMessage = decryptData(encMessage.split(":")[1] , AESKey ,new IvParameterSpec(iv));

        return decryptedMessage;
    }

    private boolean checkDates(String Key , String date){

        //System.out.println(date);
        //System.out.println(Key);

        //DateFormat df = new SimpleDateFormat("yyyy-MM-dd-hh-mm-ss");

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

        //System.out.println(currentDate);
        //System.out.println(toCompareplus5);

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

    private boolean checkIVCache(String toCheckIV){
        //System.out.println(toCheckIV);
        for (String iv:ivCache) {
            //System.out.println(iv);
            if(toCheckIV.equals(iv)){
                //System.out.println("REUSED IV");
                return true;
            }
        }
        return false;
    }

    //Based on https://www.developpez.net/forums/d1803792/java/general-java/signature-verification-rsa-java/
    private static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }
    //Based on https://www.developpez.net/forums/d1803792/java/general-java/signature-verification-rsa-java/
    private static String sign(String plainText, PrivateKey privateKey) throws Exception {

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
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

    private int SendMail(String mail){
        final String username = "alphatangototo789@gmail.com";
        final String password = "HI2LlOvoTCe2VcZtRqQD";

        SecureRandom rand = new SecureRandom(); //CREATE SECRET MDP TO SEND TO MAIL
        int tempSecret = rand.nextInt(100000);//Generation d'un entier entre 0 et 99999

        Properties prop = new Properties();
        prop.put("mail.smtp.host", "smtp.gmail.com");
        prop.put("mail.smtp.port", "587");
        prop.put("mail.smtp.auth", "true");
        prop.put("mail.smtp.starttls.enable", "true"); //TLS

        Session session = Session.getInstance(prop,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {//Sender account
                        return new PasswordAuthentication(username, password);
                    }
                });

        try {

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("alphatangototo789@gmail.com"));
            message.setRecipients(
                    Message.RecipientType.TO,
                    //InternetAddress.parse("bencochez86@gmail.com, alphatangototo789@gmail.com")//Destination mails (with a copy to sender)
                    InternetAddress.parse(mail + ", alphatangototo789@gmail.com" , true)
            );
            message.setSubject("Verification of SUPER SSD application");
            message.setText("Your code is," + "\n\n " + tempSecret);

            Transport.send(message);

            fa.appendLog("INFO","Code sent to "+mail);
            System.out.println("Code is send !");

        } catch (MessagingException e) {
            e.printStackTrace();
        }
        return tempSecret;
    }

}
