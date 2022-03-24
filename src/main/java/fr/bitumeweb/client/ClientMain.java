package fr.bitumeweb.client;


import de.mirkosertic.bytecoder.api.Export;
import de.mirkosertic.bytecoder.api.web.Element;
import de.mirkosertic.bytecoder.api.web.TextNode;
import de.mirkosertic.bytecoder.api.web.Window;

public class ClientMain {
    private static JSWebSocket socket;

    public static void main(String[] args) {
        String domain = ((CustomWindow) Window.window()).location().hostname();
        socket = JSWebSocket.create("wss://" + domain + ":8443/chat");
        socket.addEventListener("message", aEvent -> {

            TextNode node = Window.window().document().createTextNode(((DataEvent) aEvent).data() + "\n");
            Element e = Window.window().document().createElement("li");
            e.appendChild(node);
            Window.window().document().getElementById("log").appendChild(e);
            System.out.println("Message From Server " + ((DataEvent) aEvent).data());
        });
        socket.addEventListener("open", aEvent -> {
            System.out.println("Démarré !");
        });
        socket.addEventListener("error", aEvent -> {
            System.err.println("Erreur !!! " + aEvent);
        });
    }

    @Export("onSubmit")
    public static void onSubmit() {
        String rawText = ((CustomButton) Window.window().document().getElementById("message")).value();
        if (rawText.isEmpty())
            return;
        socket.send(rawText);
        ((CustomButton) Window.window().document().getElementById("message")).value("");
    }

    @Export("clearTextBox")
    public static void effacerLog() {
        Window.window().document().getElementById("log").innerHTML("");
        System.out.println("Nettoyage !");
    }
}
