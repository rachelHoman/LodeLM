package utils;

import java.util.Random;

import org.simplejavamail.api.email.Email;
import org.simplejavamail.api.mailer.*;
import org.simplejavamail.api.mailer.config.TransportStrategy;
import org.simplejavamail.email.EmailBuilder;
import org.simplejavamail.mailer.MailerBuilder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SimpleMailSender {
    private static final String SMTP_HOST = "smtp.gmail.com";
    private static final int SMTP_PORT = 587; // gmail SMTP port
    private static final String SMTP_USERNAME = "lodelm2024@gmail.com";
    private static final String SMTP_PASSWORD = "ztyb mcma dkhs oqyk";
    private static final String EMAIL_REGEX =
            "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
    private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

    /***
     * 
     * sends email from LodeLM's account
     * 
     * String to: address to send email to
     * String subject: subject of email
     * String body: email body
     * 
     */
    public static void sendEmail(String to, String subject, String body) {
        Email email = EmailBuilder.startingBlank()
                .from("LodeLM", "lodelm2024@gmail.com")
                .to(to)
                .withSubject(subject)
                .withPlainText(body)
                .buildEmail();

        Mailer mailer = MailerBuilder
                .withSMTPServer(SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD)
                .withTransportStrategy(TransportStrategy.SMTP_TLS)
                .buildMailer();

        mailer.sendMail(email);
    }

    /***
     * 
     * generates random OTP of length 6
     * 
     */
    public static String generateOTP() {
        int length = 6;
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder otp = new StringBuilder();

        // randomly generated OTP usinf characters and integers
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            otp.append(characters.charAt(random.nextInt(characters.length())));
        }

        return otp.toString();
    }

    /***
     * 
     * checks if email entered is of valid format
     * 
     * String email: the email input to be checked
     * 
     */
    public static boolean isValidEmail(String email) {
        Matcher matcher = EMAIL_PATTERN.matcher(email);
        return matcher.matches();
    }

}
