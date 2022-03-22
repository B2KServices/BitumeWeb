package fr.bitumeweb;

import com.google.gson.*;
import com.sun.net.httpserver.*;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import static java.nio.file.FileVisitOption.FOLLOW_LINKS;

public class Main {

    public static final char[] HEX_DIGITS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static JsonObject replacements;

    public static char[] encodeHex(final byte[] data) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = HEX_DIGITS[(0xF0 & data[i]) >>> 4];
            out[j++] = HEX_DIGITS[0x0F & data[i]];
        }
        return out;
    }

    public static void main(String[] args) throws IOException {
        InetSocketAddress host = new InetSocketAddress("127.0.0.1", 8080);
        WebSocketServer server = new WebSocketServer(host) {
            @Override
            public void onOpen(WebSocket webSocket, ClientHandshake clientHandshake) {
                this.broadcast("Connected");
            }

            @Override
            public void onClose(WebSocket webSocket, int i, String s, boolean b) {
                this.broadcast("Disconnected");
            }

            @Override
            public void onMessage(WebSocket webSocket, String s) {
                this.broadcast("Message : " + s);
            }

            @Override
            public void onError(WebSocket webSocket, Exception e) {

            }

            @Override
            public void onStart() {

            }
        };
        server.start();
        System.out.println("Starting server...");
        Gson gson = new Gson();
        File f = new File("secret.txt");
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
        String secret = br.readLine().trim();
        br.close();

        replacements = new JsonObject();
        try {
            replacements = JsonParser.parseReader(new FileReader("replacements.json")).getAsJsonObject();
        } catch (Throwable ignored) {
            //ignore
        }
        final JsonObject finalReplacements = replacements;
        try {
            HttpServer serv = HttpServer.create(new InetSocketAddress("127.0.0.1", 3000), 0);
            HttpContext ctx = serv.createContext("/app/setSeason", exchange -> {
                Headers resp = exchange.getResponseHeaders();
                resp.add("Content-Type", "text/plain");
                String saison = new BufferedReader(new InputStreamReader(exchange.getRequestBody())).readLine();
                finalReplacements.add("NOM_SAISON", new JsonPrimitive(saison));
                FileWriter fw = new FileWriter("replacements.json");
                gson.toJson(finalReplacements, fw);
                fw.close();
                replaceStuff();
                exchange.sendResponseHeaders(200, -1);
            });
            Authenticator auth = new Authenticator() {
                @Override
                public Result authenticate(HttpExchange exch) {
                    if (!exch.getRequestMethod().equals("POST")) {
                        return new Failure(405);
                    }
                    Headers rmap = exch.getRequestHeaders();
                    String auth = rmap.getFirst("Authorization");
                    if (auth == null) {
                        return new Retry(403);
                    }
                    if (!auth.equals(secret)) {
                        return new Failure(403);
                    }
                    return new Success(new HttpPrincipal("root", "*"));
                }
            };
            ctx.setAuthenticator(auth);


            HttpContext git = serv.createContext("/app/git", exchange -> {
                String json = exchange.getPrincipal().getRealm();
                try {
                    JsonObject jo = JsonParser.parseString(json).getAsJsonObject();
                    if (jo.has("ref") && jo.get("ref").getAsString().equals("refs/heads/master")) {
                        exchange.sendResponseHeaders(200, -1);
                        new ProcessBuilder().directory(new File(".")).command("/bin/sh", "-c", "git pull && screen -d -m mvn clean compile bytecoder:compile exec:java").start().waitFor();
                        System.exit(0); //Kill itself, if it gets to here the screen has already started
                    } else {
                        exchange.sendResponseHeaders(202, -1);
                    }
                } catch (Throwable t) {
                    t.printStackTrace();
                    exchange.sendResponseHeaders(500, -1);
                }
            });
            git.setAuthenticator(new Authenticator() {
                @Override
                public Result authenticate(HttpExchange exch) {
                    if (!exch.getRequestMethod().equals("POST")) {
                        return new Failure(405);
                    }
                    byte[] buffer;
                    try {
                        buffer = new BufferedInputStream(exch.getRequestBody()).readAllBytes();
                    } catch (IOException e) {
                        e.printStackTrace();
                        return new Retry(500);
                    }
                    SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
                    String hash;
                    try {
                        Mac mac = Mac.getInstance("HmacSHA256");
                        mac.init(secretKeySpec);
                        hash = "sha256=" + new String(encodeHex(mac.doFinal(buffer)));
                    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                        e.printStackTrace();
                        return new Retry(500);
                    }
                    Headers rmap = exch.getRequestHeaders();
                    String auth = rmap.getFirst("X-Hub-Signature-256");
                    if (!auth.equals(hash)) {
                        return new Failure(403);
                    }
                    return new Success(new HttpPrincipal("root", new String(buffer)));
                }
            });
            serv.setExecutor(null);
            serv.start();
            System.out.println("Server started ! Doing first replacement...");
            replaceStuff();
            System.out.println("First replacement done !");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void replaceStuff() {
        final Path dest = Paths.get("/var/www/bitume2000.fr/html/").normalize();
        final Path source = Paths.get(".", "pages").normalize();
        try {
            Files.walk(source, FOLLOW_LINKS).forEach((p) -> {
                p = p.normalize();
                if (Files.isDirectory(p)) {
                    try {
                        Files.createDirectories(dest.resolve(source.relativize(p)));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                } else {
                    if (p.endsWith(".html")) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        try {
                            Files.copy(p, baos);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        try {
                            String content = baos.toString("utf-8");
                            for (Map.Entry<String, JsonElement> e : replacements.entrySet()) {
                                content = content.replace(e.getKey(), e.getValue().getAsString());
                            }
                            Files.copy(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)), dest.resolve(source.relativize(p)), StandardCopyOption.REPLACE_EXISTING);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    } else {
                        try {
                            Files.copy(p, dest.resolve(source.relativize(p)), StandardCopyOption.REPLACE_EXISTING);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            });
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
