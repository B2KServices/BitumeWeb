package fr.bitumeweb.client;


import de.mirkosertic.bytecoder.api.Export;
import de.mirkosertic.bytecoder.api.web.Window;

public class ClientMain {
    private static JSWebSocket socket;

    public static void main(String[] args) {
        String domain = ((CustomWindow) Window.window()).location().hostname();
        socket = JSWebSocket.create("wss://" + domain + ":8443/chat");
        socket.addEventListener("message", aEvent -> {
            String data = Window.window().document().getElementById("log").innerHTML();
            Window.window().document().getElementById("log").innerHTML(data + ((DataEvent) aEvent).data() + "\n");
            System.out.println("Message From Server " + ((DataEvent) aEvent).data());
        });
        socket.addEventListener("open", aEvent -> {
            System.out.println("Démarré !");
        });
    }

    @Export("onSubmit")
    public static void onSubmit() {
        socket.send(((CustomButton) Window.window().document().getElementById("message")).value());
        ((CustomButton) Window.window().document().getElementById("message")).value("");
    }

    @Export("clearTextBox")
    public static void effacerLog() {
        Window.window().document().getElementById("log").innerHTML("");
        System.out.println("Nettoyage !");
    }
}
