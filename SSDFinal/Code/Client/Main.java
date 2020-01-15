import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) {
        try {
            Client ssd = new Client();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
