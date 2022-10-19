package com.code.noteme.api.tests;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.TestSuite;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.runner.RunWith;

import static io.vertx.core.http.HttpMethod.GET;
import static io.vertx.core.http.HttpMethod.POST;


@RunWith(VertxUnitRunner.class)
public class MainVerticleTests {
    private TestSuite suite = TestSuite.create("Main Test");
    private Vertx vertx;


    @Test
    public void tests() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("ping", context -> {
            HttpClient client = vertx.createHttpClient();
            client.request(GET, 8000, "localhost", "/", context.asyncAssertSuccess(req -> {
                req.send(context.asyncAssertSuccess(resp -> {
                    context.assertEquals(200, resp.statusCode());
                }));
            }));
        }).test("register", context -> {
            String user = new JsonObject().put("username", "james omondi").put("email", "cruiseomondi90@gmail.com")
                    .put("password", "Password-1").put("image-url", "").encodePrettily();
            HttpClient client = vertx.createHttpClient();
            client.request(POST, 8000, "localhost", "/register", context.asyncAssertSuccess(req -> {
                req.send(user, context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
//                    context.assertEquals("{message:")
                }));
            }));
        }).test("login", context -> {

        }).test("activate_acc", context -> {

        }).test("update_user", context -> {

        }).test("delete_user", context -> {

        }).test("reset_pass", context -> {

        }).test("logout", context -> {

        }).test("note_save", context -> {

        }).test("get_notes", context -> {

        }).test("update_note", context -> {

        }).test("delete_note", context -> {

        }).afterEach(context -> {

        });
    }

    @Test
    @DisplayName("Register")
    public void register() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("register", context -> {
            String user = new JsonObject().put("username", "james omondi").put("email", "cruiseomondi90@gmail.com")
                    .put("password", "Password-1").put("image-url", "").encodePrettily();
            HttpClient client = vertx.createHttpClient();
            client.request(POST, 8000, "localhost", "/register", context.asyncAssertSuccess(req -> {
                req.send(user, context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
//                    context.assertEquals("{message:")
                }));
            }));
        });
    }
}
