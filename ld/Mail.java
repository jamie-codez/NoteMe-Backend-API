import io.vertx.core.Vertx;
import io.vertx.ext.mail.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Mail {
    static Vertx vertx = Vertx.vertx();
    static Logger logger = LoggerFactory.getLogger(Mail.class.getName());
    private static void sendActivationMail(String email,String link) {
        MailConfig config = new MailConfig()
                .setPort(465)
                .setHostname("smtp.gmail.com")
                .setSsl(true)
                .setStarttls(StartTLSOptions.OPTIONAL)
                .setUsername("cruiseomondi90@gmail.com")
                .setPassword("rxksecgkmogjnlyv\n")
                .setLogin(LoginOption.XOAUTH2);
        MailClient client = MailClient.createShared(vertx,config,"mailme");
        MailMessage message = new MailMessage()
                .setFrom("noreply@noteme.com (No reply)")
                .setTo(email)
                .setSubject(email)
                .setText("Test message")
                .setHtml("Click link to activate account <a href=\""+link+"\">vertx.io</a>");
        client.sendMail(message,ar->{
            if (ar.succeeded()){
                logger.info("INFO: Mail sent");
            } else if (ar.failed()) {
                logger.error("ERROR: Mail not sent");
            }
        });
    }

//    public static void main(String[] args) {
//        sendActivationMail("This is a test mail");
//    }
}
