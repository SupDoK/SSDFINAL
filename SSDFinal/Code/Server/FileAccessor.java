import javax.crypto.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

public class FileAccessor {

    private KeyStore keyStore = null;

    public FileAccessor(){

        try {
            keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(null, null);

            //KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            //keyGen.init(256); // for example
            //SecretKey secretKey = keyGen.generateKey();

            //storeKeyStore();
            //getKeyStore();
            //setKeyInKeyStore(secretKey , "SuperKey");

            //storeKeyStore();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException ex) {
            ex.printStackTrace();
        }
        //createDatabase();
    }

    //Use to get data in a student file !
    public String get(String studentName){
        String fullFile = "Course           Grade";

        boolean D = false;
        try {
            D = fileIntegrity(studentName);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if(D){

            Float decrypted = null;
            SecretKey SecretKeyAES = null;

            //Float grade = null;
            String encryptedFloat = null;
            String line = null;
            String splitLine[] = null;
            BufferedReader br = null;
            try {

                getKeyStore();
                SecretKeyAES = getSecretKeyInKeyStore("SuperKey");


                File file = new File("./src/database/"+studentName);
                br = new BufferedReader(new FileReader(file));
                while ((line = br.readLine()) != null){
                    splitLine=line.split(":");
                    if(splitLine.length != 0){
                        encryptedFloat = splitLine[1];
                        decrypted = decryptDataFloat(encryptedFloat, SecretKeyAES);
                        fullFile += "\n" + splitLine[0] + "             " + decrypted;
                        //System.out.println("Course : " + splitLine[0] + ", Grades : " + decrypted);
                    }
                }
                br.close();

            } catch (IOException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException | CertificateException ex) {
                appendLog("SERVER_ERROR","Error in get function : "+ex);
            }

        }else {
            appendLog("BROKEN_FILE"," FILE INTEGRITY BROKEN !" );
            fullFile="Integrity of the notes were corrupted , please advert your admin !";
        }

        return fullFile;
    }

    //Use to connect the client
    public String connect( String username , String password){

        String[] fileArray = {"ADMIN","STUDENT","TEACHER"};
        for (String file:fileArray) {

            String answer = fileConnect(file ,username , password);
            switch (answer) {
                case "OK":
                    return file + "//" + username;
                case "NOK":
                    return "BADCRED";
                case "LOCKED":
                    return "LOCKED";
            }
        }

        return "NOTHING";
    }

    //Used by the TEACHERS to set data
    public String set(String teacherName , String studentName , String course , float grade) throws NoSuchAlgorithmException {

        boolean A = false;
        boolean D = false;
        try {
            A = fileIntegrity(course);
            D = fileIntegrity(studentName);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if(A && D){
            boolean B = fileContain(course , teacherName);
            if(B){
                boolean C = fileContain(course , studentName);
                if(C){
                        boolean F = writeFile(studentName,course,grade);
                        if(F){
                            updateHash(studentName);
                            appendLog("SUCCESSFUL_ACTION","TEACHER "+teacherName+" did change "+course + " for "+studentName);
                            return " GRADE WAS ENCODED SUCCESSFULLY ! ";
                        }else{
                            appendLog("FAILED_ACTION","TEACHER "+teacherName+" try to change "+course + " for "+studentName);
                            return " GRADE WAS NOT ENCODED ! ";
                        }
                }else{
                    appendLog("FAILED_ACTION","TEACHER "+teacherName+" try to change "+course + " for "+studentName);
                    return " STUDENT DONT ATTEND THIS COURSE ! ";
                }
            }else{
                appendLog("FAILED_ACTION","TEACHER "+teacherName+" try to change "+course + " for "+studentName);
                return " TEACHER CANNOT GRADE THIS COURSE ! ";
            }
        }else{
            appendLog("BROKEN_FILE"," FILE INTEGRITY BROKEN ! "+course+" : "+ A + " , "+studentName+" : " + D );
            return " FILE INTEGRITY BROKEN ! "+course+" : "+ A + " , "+studentName+" : " + D  ;
        }
    }

    // Used
    public String adminSet(String admin ,String studentName , String course , float grade) throws NoSuchAlgorithmException {

        boolean A = false;
        boolean D = false;
        try {
            A = fileIntegrity(course);
            D = fileIntegrity(studentName);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if(A && D){
            boolean C = fileContain(course , studentName);
            if(C){
                boolean F = writeFile(studentName,course,grade);
                if(F){
                    updateHash(studentName);
                    appendLog("SUCCESSFUL_ACTION","ADMIN "+admin+" did change "+course + " for "+studentName);
                    return " GRADE WAS ENCODED SUCCESSFULLY ! ";
                }else{
                    appendLog("FAILED_ACTION","ADMIN "+admin+" try to change "+course + " for "+studentName);
                    return " GRADE WAS NOT ENCODED ! ";
                }
            }else{
                appendLog("FAILED_ACTION","ADMIN "+admin+" try to change "+course + " for "+studentName);
                return " STUDENT DONT ATTEND THIS COURSE ! ";
            }
        }else{
            appendLog("BROKEN_FILE"," FILE INTEGRITY BROKEN ! "+course+" : "+ A + " , "+studentName+" : " + D );
            return " FILE INTEGRITY BROKEN ! "+course+" : "+ A + " , "+studentName+" : " + D  ;
        }
    }

    /*
    private void createDatabase(){

        File logins = new File("./database/logins");

        File math = new File("./database/math");
        File french = new File("./database/french");
        File student1 = new File("./database/student1");

        File hash = new File("./database/hash");

        try {
            logins.createNewFile();
            math.createNewFile();
            french.createNewFile();
            student1.createNewFile();
            hash.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }*/

    //Check if a file contain certain data !
    private boolean fileContain(String fileName , String name){

        try {

            File file = new File("./src/database/"+fileName);
            BufferedReader br = new BufferedReader(new FileReader(file));

            String line;
            while ((line = br.readLine()) != null){
                if(line.contains(name)){
                    return true;
                }
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    //Linked with the connect method ( check if a user is in the database )
    private String fileConnect(String id , String username , String password){

        String fileName = "";

        switch (id){
            case "ADMIN" :
                fileName = "AdminLogins";
                break;
            case "STUDENT" :
                fileName = "StudentLogins";
                break;
            case "TEACHER" :
                fileName = "TeachersLogins";
                break;
        }

        boolean A = false;

        try {
            updateHash(fileName);
            A = fileIntegrity(fileName);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if(A) {

            try {

                File file = new File("./src/database/" + fileName);
                BufferedReader br = new BufferedReader(new FileReader(file));

                String line;
                while ((line = br.readLine()) != null) {
                    if (line.contains(username)) {
                        String[] splitted = line.split(":");
                        int connectionsTrys = Integer.parseInt(splitted[0]);

                        if (connectionsTrys < 10) {

                            String computed = sha256(username + password);

                            if (line.contains(computed)) {
                                //Set try to 0 !
                                modifyConnectFile(fileName, line, 0);
                                updateHash(fileName);
                                return "OK";
                            } else {
                                //Set try to +1 !
                                modifyConnectFile(fileName, line, connectionsTrys + 1);
                                updateHash(fileName);
                                return "NOK";
                            }
                        } else {
                            return "LOCKED";
                        }
                    }
                }

            } catch (IOException | NoSuchAlgorithmException e) {
                appendLog("SERVER_ERROR","Error in the fileConnect function : "+e);
            }

        }else{
            appendLog("BROKEN_FILE"," FILE INTEGRITY BROKEN ! : "+fileName );
            return "BROKEN FILE";
        }

        return "NOTHING";
    }

    //Used to hash passwords
    private static String sha256(String base) {
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

    //Used to write in notes files !
    private boolean writeFile(String fileName , String course , float grade){

        String encrypted = null;

        SecretKey SecretKeyAES = null;

        if(grade < 0 || grade > 20){
            return false;
        }

        try {
            getKeyStore();
            SecretKeyAES = getSecretKeyInKeyStore("SuperKey");

            encrypted = encryptDataFloat(grade, SecretKeyAES);

            File file = new File("./src/database/"+fileName);

            List<String> fileContent = null;
            BufferedWriter writer = null;
                fileContent = new ArrayList<>(Files.readAllLines(file.toPath(), StandardCharsets.UTF_8));

                for (int i = 0; i < fileContent.size(); i++) {
                    if (fileContent.get(i).contains(course)) {
                        fileContent.set(i, course+":"+encrypted);
                        Files.write(file.toPath(), fileContent, StandardCharsets.UTF_8);
                        return true;
                    }
                }

                writer = new BufferedWriter(new FileWriter("./src/database/"+fileName, true));
                String toAppend = "\n"+course+":"+encrypted;
                writer.append(toAppend);
                writer.close();
                return true;

        } catch (CertificateException | IOException | NoSuchAlgorithmException | InvalidKeyException | UnrecoverableEntryException | InvalidAlgorithmParameterException | IllegalBlockSizeException | KeyStoreException | NoSuchPaddingException | BadPaddingException ex) {
            appendLog("SERVER_ERROR","Error in the writeFile function ! : "+ex);
        }

        return false;
    }

    //Used to check file integrity
    private boolean fileIntegrity(String fileName) throws NoSuchAlgorithmException{
        String oldHash = null;
        String hash = null;
        String line = null;
        String splitLine[] = null;
        BufferedReader br = null;

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for example
        String decrypted = null;
        SecretKey recupSecretKey = null;

        //GET old hash

        File file = new File("./src/database/hash");

        try {

            br = new BufferedReader(new FileReader(file));
            while ((line = br.readLine()) != null){
                if(line.contains(fileName)){
                    splitLine=line.split(":");
                    oldHash = splitLine[1];
                }
            }
            br.close();

            getKeyStore();
            recupSecretKey = getSecretKeyInKeyStore("SuperKey");
            decrypted = decryptData(oldHash, recupSecretKey);

            hash = getFileHash(fileName);

            if(hash.equals(decrypted)){
                //System.out.println("INTEGRITE DU FICHIER : " + fileName + " : OK");
                return true;
            }
            else{
                //appendLog("BROKEN FILE","INTEGRITE DU FICHIER : " + fileName + " : CORROMPU");
                return false;
            }

        } catch (IOException | UnrecoverableEntryException | IllegalBlockSizeException | KeyStoreException | InvalidKeyException | CertificateException | NoSuchPaddingException | BadPaddingException | InvalidAlgorithmParameterException ex) {
            appendLog("SERVER_ERROR","Error in the fileIntegrity function ! : "+ex);
        }

        return false;
    }

    //Used to update
    private void modifyConnectFile(String fileName , String line , int trys) throws IOException {

        File file = new File("./src/database/"+fileName);

        List<String> fileContent = null;
        BufferedWriter writer = null;

        fileContent = new ArrayList<>(Files.readAllLines(file.toPath(), StandardCharsets.UTF_8));

        for (int i = 0; i < fileContent.size(); i++) {
            if (fileContent.get(i).contains(line)) {

                String[] splitted = line.split(":");
                fileContent.set(i, trys+":"+splitted[1]+":"+splitted[2]);
                Files.write(file.toPath(), fileContent, StandardCharsets.UTF_8);
            }
        }
    }

    //Used to log all actions !
    public void appendLog(String type , String message){
        Date currentDate = new Date();
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd-hh-mm-ss");

        BufferedWriter writer = null;
        String toAppend = "\n"+type+"   "+message+"   "+df.format(currentDate);
        try {
            writer = new BufferedWriter(new FileWriter("./src/database/logs", true));
            writer.append(toAppend);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //Used to get the hash of a file !
    private String getFileHash(String fileName) throws IOException, NoSuchAlgorithmException {
        String encoded = null;
        MessageDigest digest = null;

        byte[] fileContentBytes = Files.readAllBytes(Paths.get("./src/database/"+fileName));
        digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(fileContentBytes);
        encoded = Base64.getEncoder().encodeToString(hash);

        return encoded;
    }

    //Used to update the hash of a file !
    private void updateHash(String fileName) throws NoSuchAlgorithmException {
        String newHash = null;

        File file = new File("./src/database/hash");
        List<String> fileContent = null;

        try {

            //CALCUL new digest
            newHash = getFileHash(fileName);
            //WRITE new digest into databases

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            String encrypted = null;
            SecretKey SecretKeyAES = null;

            getKeyStore();
            SecretKeyAES = getSecretKeyInKeyStore("SuperKey");
            encrypted = encryptData(newHash, SecretKeyAES);

            fileContent = new ArrayList<>(Files.readAllLines(file.toPath(), StandardCharsets.UTF_8));

            for (int i = 0; i < fileContent.size(); i++) {
                if (fileContent.get(i).contains(fileName)) {
                    fileContent.set(i, fileName+":"+encrypted);
                    Files.write(file.toPath(), fileContent, StandardCharsets.UTF_8);
                }
            }
        } catch (IOException | UnrecoverableEntryException | NoSuchPaddingException | CertificateException | InvalidKeyException | InvalidAlgorithmParameterException | KeyStoreException | BadPaddingException | IllegalBlockSizeException e) {
            appendLog("SERVER_ERROR","Error in the updateHash function ! : "+e);
        }
    }

    //Keystore

    private void storeKeyStore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        char[] keyStorePassword = "123abc".toCharArray();
        try (FileOutputStream keyStoreOutputStream = new FileOutputStream("./src/database/keystore.ks")) {
            keyStore.store(keyStoreOutputStream, keyStorePassword);
        }
    }

    private void getKeyStore() throws CertificateException, NoSuchAlgorithmException, IOException {
        char[] keyStorePassword = "123abc".toCharArray();
        try(InputStream keyStoreData = new FileInputStream("./src/database/keystore.ks")){
            keyStore.load(keyStoreData, keyStorePassword);
        }
    }

    private SecretKey getSecretKeyInKeyStore(String keyAlias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException {
        char[] keyPassword = "789xyz".toCharArray();
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyPassword);
        SecretKey toReturn = ((KeyStore.SecretKeyEntry)keyStore.getEntry(keyAlias, entryPassword)).getSecretKey();
        return  toReturn;
    }

    private String decryptData(String encData ,SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipherBeta = Cipher.getInstance("AES");
        cipherBeta.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] original = cipherBeta.doFinal(Base64.getDecoder().decode(encData));

        return new String(original);
    }

    private Float decryptDataFloat(String encData ,SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipherBeta = Cipher.getInstance("AES");
        cipherBeta.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] original = cipherBeta.doFinal(Base64.getDecoder().decode(encData));
        float grade = Float.parseFloat(new String(original));
        return grade;
    }


    private String encryptDataFloat(Float data , SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipherAlpha = Cipher.getInstance("AES");
        cipherAlpha.init(Cipher.ENCRYPT_MODE, secretKey);
        String grade = data.toString();
        byte[] encryptedWithAES = cipherAlpha.doFinal(grade.getBytes());
        return Base64.getEncoder().encodeToString(encryptedWithAES);
    }

    private void setKeyInKeyStore(SecretKey secretKey,String keyAlias) throws KeyStoreException {
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        char[] keyPassword = "789xyz".toCharArray();
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyPassword);
        KeyStore.SecretKeyEntry ske = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(keyAlias, ske, entryPassword);
    }


    private String encryptData(String data , SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipherAlpha = Cipher.getInstance("AES");
        cipherAlpha.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedWithAES = cipherAlpha.doFinal(data.getBytes());

        return Base64.getEncoder().encodeToString(encryptedWithAES);
    }

    //End Keystore
}