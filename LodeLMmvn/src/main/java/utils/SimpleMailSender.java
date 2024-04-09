package utils;

import java.util.Random;

import org.simplejavamail.api.email.Email;
import org.simplejavamail.api.mailer.*;
import org.simplejavamail.api.mailer.config.TransportStrategy;
import org.simplejavamail.email.EmailBuilder;
import org.simplejavamail.mailer.MailerBuilder;

public class SimpleMailSender {
    private static final String SMTP_HOST = "smtp.gmail.com";
    private static final int SMTP_PORT = 587; // gmail SMTP port
    private static final String SMTP_USERNAME = "lodelm2024@gmail.com";
    private static final String SMTP_PASSWORD = "ztyb mcma dkhs oqyk";

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
        // System.out.println("Email sent to: " + to);
        // System.out.println("Subject: " + subject);
        // System.out.println("Body: " + body);
    }

    public static String generateOTP() {
        int length = 6;
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder otp = new StringBuilder();

        Random random = new Random();
        for (int i = 0; i < length; i++) {
            otp.append(characters.charAt(random.nextInt(characters.length())));
        }

        return otp.toString();
    }



}
