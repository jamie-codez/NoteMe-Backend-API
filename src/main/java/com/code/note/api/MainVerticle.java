package com.code.note.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.mail.*;
import io.vertx.ext.mongo.MongoClient;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.*;

public class MainVerticle extends AbstractVerticle {
    private final Logger logger = LoggerFactory.getLogger(Class.class.getName());
    static private final Vertx vertx = Vertx.vertx();
    MongoClient mongoClient;
    public static final String USER_DB = "users";
    public static final String NOTES_DB = "notes";
    public static final String JWT_DB = "jwt";
    public static final String ACTIVATION_CODE_DB = "activation-code-db";
    private DeploymentOptions options;

    @Override
    public void start() throws Exception {
        super.start();
        options = new DeploymentOptions().setConfig(new JsonObject()
                .put("http.port", 8000)
                .put("host_name", "smtp.google.com")
                .put("username", "cruiseomondi90@gmail.com")
                .put("app_password", "rxksecgkmogjnlyv\n"));
        JsonObject dbConfig = new JsonObject()
                .put("db_name", "note_me")
                .put("connection_string", "mongodb://localhost:27017");
        mongoClient = MongoClient.create(vertx, dbConfig);
        Router router = Router.router(vertx);
        router.get("/").handler(this::handlePing);
        router.post("/register").handler(this::register);
        router.post("/login").handler(this::login);
        router.get("/users/activate/:code").handler(this::activateAccount);
        router.put("/users/update/:email").handler(this::updateUserProfile);
        router.delete("/users/delete/:email").handler(this::deleteAccount);
        router.delete("/logout/:email").handler(this::logout);
        router.post("/reset/password/:email").handler(this::resetPassword);
        router.get("/reset/password/:email").handler(this::sendPasswordResetEmail);
        router.post("/notes/save").handler(this::saveNote);
        router.get("/notes").handler(this::getMyNotes);
        router.put("/notes/update").handler(this::updateNote);
        router.delete("/notes/delete").handler(this::deleteNotes);
        vertx.createHttpServer().requestHandler(router).listen(options.getConfig().getInteger("http.port"), ar -> {
            if (ar.succeeded()) {
                System.out.println("> INFO: Server running on port: " + options.getConfig().getInteger("http.port", 8001));
                logger.debug("> INFO: Server running on port: " + options.getConfig().getInteger("http.port", 8001));
            } else if (ar.failed()) {
                System.out.println("> ERROR: Error starting server...");
                logger.debug("> ERROR: Error starting server...");
            }
        });
    }

    private void handlePing(RoutingContext rc) {
        rc.response().setStatusCode(200)
                .putHeader("content-type", "application/json")
                .end(new JsonObject().put("message", "Server running on port:" + options.getConfig().getInteger("http.port", 8001)).encodePrettily());
        logger.info("Ping route");
    }

    public void register(@NotNull RoutingContext rc) {
        rc.request().bodyHandler(bodyHandler -> {
            JsonObject user = bodyHandler.toJsonObject();
            // Check if user already exists
            JsonObject query = new JsonObject().put("email", user.getValue("email").toString());
            mongoClient.findOne(USER_DB, query, null, res -> {
                if (res.succeeded()) {
                    if (res.result() == null) {
                        JsonObject userDoc = new JsonObject()
                                .put("username", user.getValue("username"))
                                .put("email", user.getValue("email"))
                                .put("password", new BCryptPasswordEncoder().encode(user.getValue("password").toString()))
                                .put("image-url", user.getValue("image_url"))
                                .put("verified", false);
//                        logger.info(res.result().toString());
                        mongoClient.insert(USER_DB, userDoc, result -> {
                            if (result.succeeded()) {
                                String code = UUID.randomUUID().toString();
                                var link = rc.request().localAddress().host() + ":" + options.getConfig().getInteger("http.port", 8001) + "/users/activate/" + code;
                                sendActivationMail(userDoc.getValue("email").toString(), link, code);
                                rc.response()
                                        .putHeader("content-type", "application/json")
                                        .setStatusCode(201)
                                        .end(new JsonObject().put("message", "User created successfully...\n" +
                                                "Check your email to activate account and login to app").encodePrettily());
                            } else {
                                rc.response()
                                        .putHeader("content-type", "application/json")
                                        .setStatusCode(500)
                                        .end(new JsonObject().put("message", "Error creating user try again").encodePrettily());
                            }
                        });
                    } else if (res.result()!=null) {
                        rc.response()
                                .putHeader("content-type", "application/json")
                                .setStatusCode(400)
                                .end(new JsonObject().put("message", "User already exists...").encodePrettily());
                    }
                } else if (res.failed()) {
                    rc.response()
                            .putHeader("content-type", "application/json")
                            .setStatusCode(500)
                            .end(new JsonObject().put("message", "Error registering").encodePrettily());
                }
            });
        });
    }

    public void activateAccount(RoutingContext rc) {
        var token = rc.request().getParam("code");
        mongoClient.findOne(ACTIVATION_CODE_DB, new JsonObject().put("code", token), null, ar -> {
            if (ar.succeeded()) {
                if (ar.result() == null) {
                    rc.response()
                            .putHeader("content-type", "application/json")
                            .setStatusCode(400)
                            .end(new JsonObject().put("message", "Link already used").encodePrettily());
                } else {
                    mongoClient.findOneAndUpdate(USER_DB,
                            new JsonObject().put("email", ar.result().getValue("email")),
                            new JsonObject().put("$set", new JsonObject().put("verified", true)),
                            res -> {
                                if (res.succeeded()) {
                                    logger.info("INFO: Activation successful");
                                } else if (res.failed()) {
                                    logger.error("ERROR: Activation failed");
                                }
                            });
                    mongoClient.findOneAndDelete(ACTIVATION_CODE_DB, new JsonObject().put("code", token), re -> {
                        if (re.succeeded()) {
                            logger.info(">INFO: Deleting activation code successful");
                        } else if (re.failed()) {
                            logger.error(">INFO: Deleting activation code failed");
                        }
                    });
                    rc.response()
                            .putHeader("content-type", "application/json")
                            .setStatusCode(200)
                            .end(new JsonObject().put("message", "Activation successful").encodePrettily());
                }
            } else if (ar.failed()) {
                rc.response()
                        .putHeader("content-type", "application/json")
                        .setStatusCode(400)
                        .end(new JsonObject().put("message", "Invalid token").encodePrettily());
            }
        });
    }

    public void sendPasswordResetEmail(RoutingContext rc) {
        String email = rc.request().getParam("email");
        var link = rc.request().localAddress().host() + ":" + options.getConfig().getInteger("http.port", 8001) + "/reset/password/" + email;
        mongoClient.findOne(USER_DB, new JsonObject().put("email", email), null, ar -> {
            if (ar.failed()) {
                rc.response()
                        .putHeader("content-type", "application/json")
                        .setStatusCode(400)
                        .end(new JsonObject().put("message", "Error occurred").encodePrettily());
            } else {
                if (ar.result() != null) {
                    MailConfig config = new MailConfig()
                            .setPort(465)
                            .setHostname("smtp.gmail.com")
                            .setSsl(true)
                            .setStarttls(StartTLSOptions.OPTIONAL)
                            .setUsername("cruiseomondi90@gmail.com")
                            .setPassword("rxksecgkmogjnlyv\n")
                            .setLogin(LoginOption.XOAUTH2);
                    String htmlString = String.format("<a href=\"http://%s\">Reset password</a>", link);
                    MailClient client = MailClient.createShared(vertx, config, "mailme");
                    MailMessage message = new MailMessage()
                            .setFrom("noreply@noteme.com (No reply)")
                            .setTo(email)
                            .setSubject("Account activation")
                            .setText("Test message")
                            .setHtml("Click link to activate account." + htmlString);
                    client.sendMail(message, re -> {
                        if (re.succeeded()) {
                            logger.info("INFO: Mail sent");

                        } else if (re.failed()) {
                            logger.error("ERROR: Mail not sent");
                        }
                    });
                } else {
                    rc.response()
                            .putHeader("content-type", "application/json")
                            .setStatusCode(400)
                            .end(new JsonObject().put("message", "Error occurred").encodePrettily());
                }
            }
        });
    }

    public void resetPassword(RoutingContext rc) {
        rc.request().bodyHandler(handler -> {
            var reqBody = handler.toJsonObject();
            String email = reqBody.getValue("email").toString();
            mongoClient.findOne(USER_DB, new JsonObject().put("email", email), null, ar -> {
                if (ar.failed()) {
                    rc.response()
                            .putHeader("content-type", "application/json")
                            .setStatusCode(400)
                            .end(new JsonObject().put("message", "Error occurred").encodePrettily());
                } else {
                    mongoClient.findOneAndUpdate(USER_DB, new JsonObject().put("email", email), new JsonObject().put("$set", reqBody), re -> {
                        rc.response()
                                .putHeader("content-type", "application/json")
                                .setStatusCode(400)
                                .end(new JsonObject().put("message", "Password reset successfully").encodePrettily());
                    });
                }
            });
        });
    }


    private void sendActivationMail(String email, String link, String code) {
        MailConfig config = new MailConfig()
                .setPort(465)
                .setHostname("smtp.gmail.com")
                .setSsl(true)
                .setStarttls(StartTLSOptions.OPTIONAL)
                .setUsername("cruiseomondi90@gmail.com")
                .setPassword("rxksecgkmogjnlyv\n")
                .setLogin(LoginOption.XOAUTH2);
        String htmlString = String.format("<a href=\"http://%s\"> Activate account</a>", link);
        MailClient client = MailClient.createShared(vertx, config, "mailme");
        MailMessage message = new MailMessage()
                .setFrom("noreply@noteme.com (No reply)")
                .setTo(email)
                .setSubject("Account activation")
                .setText("Test message")
                .setHtml("Click link to activate account." + htmlString);
        client.sendMail(message, ar -> {
            if (ar.succeeded()) {
                logger.info("INFO: Mail sent");
                mongoClient.insert(ACTIVATION_CODE_DB, new JsonObject().put("email", email).put("code", code), res -> {
                    if (res.succeeded()) {
                        logger.info("INFO: Activation link saved");
                    } else if (res.failed()) {
                        logger.error("ERROR: Failed saving activation link.");
                    }
                });
            } else if (ar.failed()) {
                logger.error("ERROR: Mail not sent");
            }
        });
    }

    public void updateUserProfile(RoutingContext rc) {
        rc.request().connection().localAddress().host();
        rc.request().bodyHandler(bodyHandler -> {
            JsonObject body = bodyHandler.toJsonObject();
            var jwt = rc.request().getHeader("access-token");
            if (jwt != null) {
                JWTVerifier verifier = JWT.require(Algorithm.HMAC256("secret")).withIssuer("noteme.com").build();
                var email = rc.request().getParam("email");
                mongoClient.findOne(USER_DB, new JsonObject().put("email", email), null, ar -> {
                    if (ar.succeeded()) {
                        if (ar.result() == null) {
                            rc.response()
                                    .putHeader("content-type", "application/json")
                                    .setStatusCode(500)
                                    .end(new JsonObject().put("message", "Invalid request").encodePrettily());
                        }
                        DecodedJWT decodedJWT = verifier.verify(jwt);
                        var subject = decodedJWT.getSubject();
                        if (Objects.equals(email, subject)) {
                            if (body.containsKey("password")) {
                                var password = new BCryptPasswordEncoder().encode(body.getValue("password").toString());
                                body.put("password", password);
                            }
                            mongoClient.findOneAndUpdate(USER_DB, new JsonObject().put("email", email), new JsonObject().put("$set", body), re -> {
                                if (re.succeeded()) {
                                    rc.response()
                                            .putHeader("content-type", "application/json")
                                            .setStatusCode(200)
                                            .end(new JsonObject().put("message", "User profile updated successfully").encodePrettily());
                                } else if (re.failed()) {
                                    rc.response()
                                            .putHeader("content-type", "application/json")
                                            .setStatusCode(400)
                                            .end(new JsonObject().put("message", "Error updating user profile").encodePrettily());
                                }
                            });
                        }
                    } else if (ar.failed()) {
                        rc.response()
                                .putHeader("content-type", "application/json")
                                .setStatusCode(500)
                                .end(new JsonObject().put("message", ar.cause().getMessage()).encodePrettily());
                    }
                });
            } else {
                rc.response()
                        .putHeader("content-type", "application/json")
                        .setStatusCode(500)
                        .end(new JsonObject().put("message", "Access token absent").encodePrettily());
            }
        });
    }

    public void deleteAccount(RoutingContext rc) {
        var email = rc.request().getParam("email");
        var jwt = rc.request().getHeader("access-token");
        if (jwt != null) {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256("secret")).withIssuer("noteme.com").build();
            DecodedJWT decodedJWT = verifier.verify(jwt);
            String subject = decodedJWT.getSubject();
            if (Objects.equals(subject, email)) {
                mongoClient.findOne(USER_DB, new JsonObject().put("email", email), null, ar -> {
                    if (ar.succeeded()) {
                        if (ar.result() == null) {
                            rc.response()
                                    .putHeader("content-type", "application/json")
                                    .setStatusCode(400)
                                    .end(new JsonObject().put("message", "Error deleting account").encodePrettily());
                        }
                        mongoClient.findOneAndDelete(USER_DB, new JsonObject().put("email", email), re -> {
                            if (re.succeeded()) {
                                logout(rc);
                                rc.response()
                                        .putHeader("content-type", "application/json")
                                        .setStatusCode(200)
                                        .end(new JsonObject().put("message", "Successfully deleted account").encodePrettily());
                            } else if (re.failed()) {
                                rc.response()
                                        .putHeader("content-type", "application/json")
                                        .setStatusCode(400)
                                        .end(new JsonObject().put("message", "Error deleting account").encodePrettily());
                            }
                        });
                    } else if (ar.failed()) {
                        rc.response()
                                .putHeader("content-type", "application/json")
                                .setStatusCode(500)
                                .end(new JsonObject().put("message", ar.cause().getMessage()).encodePrettily());
                    }
                });
            } else {
                rc.response()
                        .putHeader("content-type", "application/json")
                        .setStatusCode(400)
                        .end(new JsonObject().put("message", "Invalid request").encodePrettily());
            }
        } else {
            rc.response()
                    .setStatusCode(400)
                    .putHeader("content-type", "application/json")
                    .end(new JsonObject().put("message", "Access token absent").encodePrettily());
        }

    }

    private void saveJwt(String jwt, String email) {
        mongoClient.findOne(JWT_DB, new JsonObject().put("owner", email), null, ar -> {
            if (ar.succeeded() && ar.result() == null) {
                mongoClient.save(JWT_DB, new JsonObject().put("owner", email).put("jwt", jwt), re -> {
                    if (re.succeeded()) logger.info("JWT saved successfully");
                });
            } else if (ar.succeeded() && ar.result() != null) {
                mongoClient.findOneAndDelete(JWT_DB, new JsonObject().put("owner", email), re -> {
                    if (re.succeeded()) {
                        mongoClient.save(JWT_DB, new JsonObject().put("owner", email).put("jwt", jwt), res -> {
                            if (res.succeeded()) logger.info("JWT saved successfully");
                        });
                    }
                });
            }
        });
    }

    public void login(@NotNull RoutingContext rc) {
        rc.request().bodyHandler(bodyHandler -> {
            JsonObject login = bodyHandler.toJsonObject();
            mongoClient.findOne(USER_DB, new JsonObject().put("email", login.getValue("email")), null, res -> {
                if (res.succeeded() && Boolean.parseBoolean(res.result().getValue("verified").toString())) {
                    if (res.result() != null) {
                        if (new BCryptPasswordEncoder().matches(login.getValue("password").toString(), res.result().getString("password"))) {
                            Map<String, String> payload = new HashMap<>();
                            payload.put("email", res.result().getValue("email").toString());
                            String jwt = JWT.create()
                                    .withPayload(payload)
                                    .withSubject(res.result().getValue("email").toString())
                                    .withIssuer("noteme.com")
                                    .sign(Algorithm.HMAC256("secret".getBytes()));
                            saveJwt(jwt, res.result().getValue("email").toString());
                            rc.response()
                                    .setStatusCode(200)
                                    .putHeader("content-type", "application/json")
                                    .end(new JsonObject().put("message", "Login successful").put("access-token", jwt).encodePrettily());
                        }
                    } else {
                        rc.response()
                                .setStatusCode(400)
                                .putHeader("content-type", "application/json")
                                .end(new JsonObject().put("message", "Invalid credentials").encodePrettily());
                    }
                } else {
                    rc.response()
                            .setStatusCode(403)
                            .putHeader("content-type", "application/json")
                            .end(new JsonObject().put("message", "Account not verified yet").encodePrettily());
                }

            });
        });
    }

    public void logout(@NotNull RoutingContext rc) {
        var email = rc.request().getParam("email");
        mongoClient.findOneAndDelete(JWT_DB, new JsonObject().put("owner", email), ar -> {
            if (ar.succeeded()) {
                rc.response()
                        .putHeader("content-type", "application/json")
                        .setStatusCode(200).end(new JsonObject().put("message", "Logout successful").encodePrettily());
            } else if (ar.failed()) {
                rc.response()
                        .putHeader("content-type", "application/json")
                        .setStatusCode(400).end(new JsonObject().put("message", "Logout unsuccessful").encodePrettily());
            }
        });
    }

    public void saveNote(@NotNull RoutingContext rc) {
        rc.request().bodyHandler(bodyHandler -> {
            String accessToken = rc.request().getHeader("access-token");
            JsonObject note = bodyHandler.toJsonObject();
            if (accessToken == null) {
                rc.response()
                        .setStatusCode(403)
                        .putHeader("content-type", "application/json")
                        .end(new JsonObject().put("message", "Access token not provided").encodePrettily());
            }
            mongoClient.findOne(JWT_DB, new JsonObject().put("owner", note.getValue("owner").toString()), null, results -> {
                if (results.succeeded()) {
                    if (results.result() == null) {
                        rc.response()
                                .setStatusCode(403)
                                .putHeader("content-type", "application/json")
                                .end(new JsonObject().put("message", "Invalid access token").encodePrettily());
                    }
                    JsonObject noteDoc = new JsonObject()
                            .put("title", note.getValue("title"))
                            .put("owner", note.getValue("owner"))
                            .put("note", note.getValue("note"))
                            .put("createdAt",System.currentTimeMillis());
                    JWTVerifier verifier = JWT.require(Algorithm.HMAC256("secret")).withIssuer("noteme.com").build();
                    try {
                        assert accessToken != null;
                        DecodedJWT verify = verifier.verify(accessToken);
                        var email = verify.getSubject();
                        if (email.equals(note.getValue("owner"))) {
                            mongoClient.save(NOTES_DB, noteDoc, ar -> {
                                if (ar.succeeded()) {
                                    rc.response()
                                            .putHeader("content-type", "application/json")
                                            .setStatusCode(201)
                                            .end(new JsonObject().put("message", "Note saved successfully").encodePrettily());
                                } else if (ar.failed()) {
                                    rc.response()
                                            .putHeader("content-type", "application/json")
                                            .setStatusCode(500)
                                            .end(new JsonObject().put("message", "Error saving note 1"+ar.cause().getMessage()).encodePrettily());
                                }
                            });
                        } else {
                            rc.response().putHeader("content-type", "application/json").setStatusCode(500).end(new JsonObject().put("message", "Error saving note 2").encodePrettily());
                        }
                    } catch (Exception e) {
                        rc.response().putHeader("content-type", "application/json").setStatusCode(500).end(new JsonObject().put("message", e.getMessage()).encodePrettily());
                        logger.error(e.getMessage());
                    }
                }
            });
        });
    }

    public void getMyNotes(@NotNull RoutingContext rc) {
        var jwt = rc.request().getHeader("access-token");
        if (jwt == null) {
            rc.response()
                    .setStatusCode(403)
                    .putHeader("content-type", "application/json")
                    .end(new JsonObject().put("message", "No access token provided").encodePrettily());
        } else {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256("secret")).withIssuer("noteme.com").build();
            try {
                DecodedJWT decodedJWT = verifier.verify(jwt);
                var email = decodedJWT.getSubject();
                mongoClient.find(NOTES_DB, new JsonObject().put("owner", email), ar -> {
                    if (ar.succeeded()) {
                        rc.response()
                                .putHeader("content-type", "application/json")
                                .setStatusCode(200)
                                .end(new JsonObject().put("notes", ar.result()).encodePrettily());
                    } else if (ar.failed()) {
                        rc.response()
                                .putHeader("content-type", "application/json")
                                .setStatusCode(503)
                                .end(new JsonObject().put("message", "Error getting notes").encodePrettily());
                    }
                });
            } catch (Exception e) {
                rc.response()
                        .putHeader("content-type", "application/json")
                        .setStatusCode(500)
                        .end(new JsonObject().put("message", e.getMessage()).encodePrettily());
                logger.error(e.getMessage());
            }
        }
    }

    public void updateNote(@NotNull RoutingContext rc) {
        rc.request().bodyHandler(bodyHandler -> {
            JsonObject update = bodyHandler.toJsonObject();
            var id = update.getValue("_id");
            JsonObject updateDoc = new JsonObject().put("$set", update);
            var jwt = rc.request().getHeader("access-token");
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256("secret")).withIssuer("noteme.com").build();
            DecodedJWT decodedJWT = verifier.verify(jwt);
            var email = decodedJWT.getSubject();
            try {
                if (email == update.getValue("owner")) {
                    mongoClient.findOne(NOTES_DB, new JsonObject().put("_id", id), null, ar -> {
                        if (ar.succeeded() && ar.result() != null) {
                            mongoClient.findOneAndUpdate(NOTES_DB, new JsonObject().put("_id", id), updateDoc, res -> {
                                if (res.succeeded()) {
                                    rc.response()
                                            .putHeader("content-type", "application/json")
                                            .setStatusCode(200)
                                            .end(new JsonObject().put("message", "Note updated successfully").encodePrettily());
                                } else if (res.failed()) {
                                    rc.response()
                                            .putHeader("content-type", "application/json")
                                            .setStatusCode(400)
                                            .end(new JsonObject().put("message", "Error updating note").encodePrettily());
                                }
                            });
                        } else {
                            rc.response()
                                    .putHeader("content-type", "application/json")
                                    .setStatusCode(400)
                                    .end(new JsonObject().put("message", "Error occurred").encodePrettily());
                        }
                    });
                } else {
                    rc.response()
                            .putHeader("content-type", "application/json")
                            .setStatusCode(403)
                            .end(new JsonObject().put("message", "Invalid request").encodePrettily());
                }
            } catch (Exception e) {
                rc.response()
                        .putHeader("content-type", "application/json")
                        .setStatusCode(500)
                        .end(new JsonObject().put("message", "Internal server error").encodePrettily());
            }
        });
    }

    public void deleteNotes(@NotNull RoutingContext rc) {
        rc.request().bodyHandler(bodyHandler -> {
            JsonObject body = bodyHandler.toJsonObject();
            var jwt = rc.request().getHeader("access-token");
            if (jwt == null) {
                rc.response()
                        .putHeader("content-type", "application/json")
                        .setStatusCode(400)
                        .end(new JsonObject().put("message", "No access token provided").encodePrettily());
            } else {
                JWTVerifier verifier = JWT.require(Algorithm.HMAC256("secret")).withIssuer("noteme.com").build();
                try {
                    DecodedJWT decodedJWT = verifier.verify(jwt);
                    var email = decodedJWT.getSubject();
                    if (email == body.getValue("owner")) {
                        mongoClient.findOneAndDelete(NOTES_DB, body, res -> {
                            if (res.succeeded()) {
                                rc.response()
                                        .putHeader("content-type", "application/json")
                                        .setStatusCode(200)
                                        .end(new JsonObject().put("message", "Note deleted successfully").encodePrettily());
                            } else if (res.failed()) {
                                rc.response()
                                        .putHeader("content-type", "application/json")
                                        .setStatusCode(503)
                                        .end(new JsonObject().put("message", "Error deleting note").encodePrettily());
                            }
                        });
                    } else {
                        rc.response()
                                .putHeader("content-type", "application/json")
                                .setStatusCode(400)
                                .end(new JsonObject().put("message", "Action not permitted").encodePrettily());
                    }
                } catch (Exception e) {
                    rc.response()
                            .putHeader("content-type", "application/json")
                            .setStatusCode(500)
                            .end(new JsonObject().put("message", "Error getting notes").encodePrettily());
                }
            }
        });
    }


    @Override
    public void stop() throws Exception {
        super.stop();
    }

    public static void main(String[] args) {
        MainVerticle verticle = new MainVerticle();
        vertx.deployVerticle(verticle);
    }
}
