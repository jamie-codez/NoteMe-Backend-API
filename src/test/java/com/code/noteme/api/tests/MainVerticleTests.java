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

import static io.vertx.core.http.HttpMethod.*;


@RunWith(VertxUnitRunner.class)
public class MainVerticleTests {
    private final TestSuite suite = TestSuite.create("Main Test");
    private Vertx vertx;
    private final String authToken = "";


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
                    context.assertEquals("{\n" +
                            "  \"message\": \"User created successfully...\"\n" +
                            "}", res.body());
                }));
            }));
        }).afterEach(context -> {

        });
    }

    @Test
    @DisplayName("Register")
    public void registerTest() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("register", context -> {
            String user = new JsonObject().put("username", "james omondi").put("email", "cruiseomondi90@gmail.com")
                    .put("password", "Password-1").put("image-url", "").encodePrettily();
            HttpClient client = vertx.createHttpClient();
            client.request(POST, 8000, "localhost", "/register", context.asyncAssertSuccess(req -> {
                req.send(user, context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
                    context.assertEquals("{\n" +
                            "  \"message\": \"User created successfully...\"\n" +
                            "}", res.body());
                }));
            }));
        }).after(context -> {
            vertx.close();
        });
    }

    @Test
    @DisplayName("Activate account")
    public void activateAccountTest() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("activate_acc", context -> {
            String activationCode = "";
            HttpClient client = vertx.createHttpClient();
            client.request(GET, 8000, "localhost", "/users/activate/" + activationCode, context.asyncAssertSuccess(req -> {
                req.send(context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
                }));
            }));
        }).after(context -> {
            vertx.close();
        });
    }

    @Test
    @DisplayName("Update user")
    public void updateUserTest() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("update_user", context -> {
            HttpClient client = vertx.createHttpClient();
            String email = "test@mail.com";
            String user = new JsonObject().put("username", "james omondi").put("email", "cruiseomondi90@gmail.com")
                    .put("password", "Password-1").put("image-url", "").encodePrettily();
            client.request(POST, 8000, "localhost", "/users/" + email, context.asyncAssertSuccess(req -> {
                req.send(user, context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
                }));
            }));
        }).after(context -> {
            vertx.close();
        });
    }

    @Test
    @DisplayName("Login")
    public void loginTest() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("Login", context -> {
            String user = new JsonObject().put("email", "test@gmail.com").put("password", "Password-1").encodePrettily();
            HttpClient client = vertx.createHttpClient();
            client.request(POST, 8000, "localhost", "/login", context.asyncAssertSuccess(req -> {
                req.send(user, context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
                }));
            }));
        }).after(context -> {
            vertx.close();
        });
    }

    @Test
    @DisplayName("Delete user")
    public void deleteUserTest() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("delete_user", context -> {
            String user = new JsonObject().put("username", "james omondi").put("email", "cruiseomondi90@gmail.com")
                    .put("password", "Password-1").put("image-url", "").encodePrettily();
            HttpClient client = vertx.createHttpClient();
            String email = "test@gmail.com";
            client.request(DELETE, 8000, "localhost", "/users/delete/" + email, context.asyncAssertSuccess(req -> {
                req.send(user, context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
                }));
            }));
        }).after(context -> {
            vertx.close();
        });
    }

    @Test
    @DisplayName("Reset password")
    public void resetPassTest() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("reset_pass", context -> {
            HttpClient client = vertx.createHttpClient();
            String email = "test@gmail.com";
            client.request(PUT, 8000, "localhost", "/reset/" + email, context.asyncAssertSuccess(req -> {
                req.send(context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
                }));
            }));
        }).after(context -> {
            vertx.close();
        });
    }

    @Test
    @DisplayName("Save note")
    public void saveNoteTest() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("note_save", context -> {
            HttpClient client = vertx.createHttpClient();
            String user = new JsonObject().put("title", "Test note").put("owner", "test@gmail.com").put("note", "Test note to self").encodePrettily();
            client.request(POST, 8000, "localhost", "/notes/save", context.asyncAssertSuccess(req -> {
                req.send(user, context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
                }));
            }));
        }).after(context -> {
            vertx.close();
        });
    }

    @Test
    @DisplayName("Get notes")
    public void getNotesTest() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("get_notes", context -> {
            HttpClient client = vertx.createHttpClient();
            client.request(GET, 8000, "localhost", "/notes", context.asyncAssertSuccess(req -> {
                req.send( context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
                }));
            }));
        }).after(context -> {
            vertx.close();
        });
    }

    @Test
    @DisplayName("Update note")
    public void updateNoteTest() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("update_note", context -> {
            HttpClient client = vertx.createHttpClient();
            String user = new JsonObject().put("title", "Test note").put("owner", "test@gmail.com").put("note", "Test note to self").encodePrettily();
            client.request(POST, 8000, "localhost", "/notes/update", context.asyncAssertSuccess(req -> {
                req.send(user, context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
                }));
            }));
        }).after(context -> {
            vertx.close();
        });
    }

    @Test
    @DisplayName("Delete note")
    public void deleteNoteTest() {
        suite.beforeEach(context -> {
            vertx = Vertx.vertx();
        }).test("delete_note", context -> {
            HttpClient client = vertx.createHttpClient();
            String email = "test@gmail.com";
            client.request(DELETE, 8000, "localhost", "/notes/delete?email="+email, context.asyncAssertSuccess(req -> {
                req.send( context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());
                }));
            }));
        }).after(context -> {
            vertx.close();
        });
    }
}
