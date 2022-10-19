package com.code.noteme.api.tests;

import com.code.note.api.MainVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxTestContext;
import org.assertj.core.api.Assertions;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.Assert.*;

public class MainVerticleTest {
    private HttpClient httpClient;
    private WebClient webClient;
    private Vertx vertx;
    private VertxTestContext testContext;
    private MainVerticle mainVerticle;

    @Before
    public void setUp() throws Exception {
        vertx = Vertx.vertx();
        mainVerticle = new MainVerticle();
        httpClient = vertx.createHttpClient();
        webClient = WebClient.create(vertx);
        vertx = Vertx.vertx();
        testContext = new VertxTestContext();
    }

//    @After
//    public void tearDown() throws Exception {
//        httpClient.close();
//        webClient.close();
//        vertx.close();
//        testContext.completed();
//    }

    @Test
    public void register() {
        String s = new JsonObject().put("username", "james omondi").put("email", "cruiseomondi90@gmail.com")
                .put("password", "Password").put("image-url", "").encodePrettily();
        webClient.post(8000,"localhost","/register")
                .sendBuffer(Buffer.buffer(s),ar->{
                    if (ar.succeeded()){
                        System.out.println("Succeed");
                    }else {
                        System.out.println("Failed");
                    }
                });
    }

    @Test
    public void activateAccount() {
    }

    @Test
    public void sendPage() {
    }

    @Test
    public void sendPasswordResetEmail() {
    }

    @Test
    public void resetPassword() {
    }

    @Test
    public void updateUserProfile() {
    }

    @Test
    public void deleteAccount() {
    }

    @Test
    public void login() {
    }

    @Test
    public void logout() {
    }

    @Test
    public void saveNote() {
    }

    @Test
    public void getMyNotes() {
    }

    @Test
    public void updateNote() {
    }

    @Test
    public void deleteNotes() {
    }
}