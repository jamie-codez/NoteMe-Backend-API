import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

public class ConfigVerticle extends AbstractVerticle {
    static final Vertx vertx = Vertx.vertx();

    @Override
    public void start() throws Exception {
        super.start();
        Router router = Router.router(vertx);
        router.get().handler(this::sendConfig);
        vertx.createHttpServer().requestHandler(router)
                .listen(9000,ar->{
                    if (ar.failed())
                        System.out.println("ERROR: Config server failed to start");
                    else
                        System.out.println("INFO: Config server started successfully");
                });
    }

    public void sendConfig(RoutingContext rc) {
        rc.response().setStatusCode(200)
                .putHeader("content-type", "application/json")
                .end(
                        new JsonObject()
                                .put("http.port", 8000)
                                .put("host_name", "smtp.google.com")
                                .put("username", "cruiseomondi90@gmail.com")
                                .put("app_password", "rxksecgkmogjnlyv\n")
                                .encodePrettily()
                );
    }

    public static void main(String[] args) {
        vertx.deployVerticle(new ConfigVerticle());
    }
}
