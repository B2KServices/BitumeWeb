package fr.bitumeweb;

import com.google.gson.*;
import com.sun.net.httpserver.*;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.DefaultSSLWebSocketServerFactory;
import org.java_websocket.server.WebSocketServer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
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
        InetSocketAddress host = new InetSocketAddress("0.0.0.0", 8443);
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
                System.out.println("Erreur websocket");
                e.printStackTrace();
            }

            @Override
            public void onStart() {
                System.out.println("Websocket démarré");
            }
        };
        SSLContext context = getContext();
        if (context != null) {
            server.setWebSocketFactory(new DefaultSSLWebSocketServerFactory(context));
        } else {
            System.out.println("WARNING !!! context is null ! using unsecure websocket");
        }
        server.setConnectionLostTimeout(30);
        server.start();
        //En cas d'arrêt, stopper le serveur pour s'assurer que le port est libéré
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                server.stop(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }));
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

    private static SSLContext getContext() {
        SSLContext context;
        String password = "ThisDoesNotMatter";
        String pathname = "certs";
        try {
            context = SSLContext.getInstance("TLS");

            byte[] certBytes = parseDERFromPEM(getBytes(new File(pathname + File.separator + "cert.pem")),
                    "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
            byte[] keyBytes = parseDERFromPEM(
                    getBytes(new File(pathname + File.separator + "privkey.pem")),
                    "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");

            X509Certificate cert = generateCertificateFromDER(certBytes);
            RSAPrivateKey key = generatePrivateKeyFromDER(keyBytes);

            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(null);
            keystore.setCertificateEntry("cert-alias", cert);
            keystore.setKeyEntry("key-alias", key, password.toCharArray(), new Certificate[]{cert});

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keystore, password.toCharArray());

            KeyManager[] km = kmf.getKeyManagers();

            context.init(km, null, null);
        } catch (Exception e) {
            e.printStackTrace();
            context = null;
        }
        return context;
    }

    private static byte[] parseDERFromPEM(byte[] pem, String beginDelimiter, String endDelimiter) {
        String data = new String(pem);
        String[] tokens = data.split(beginDelimiter);
        tokens = tokens[1].split(endDelimiter);

        return Base64.getDecoder().decode(tokens[0].replace("\n", ""));
    }

    private static RSAPrivateKey generatePrivateKeyFromDER(byte[] keyBytes)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        return (RSAPrivateKey) factory.generatePrivate(spec);
    }

    private static X509Certificate generateCertificateFromDER(byte[] certBytes)
            throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    private static byte[] getBytes(File file) {
        byte[] bytesArray = new byte[(int) file.length()];

        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            fis.read(bytesArray); //read file into bytes[]
            fis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bytesArray;
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
