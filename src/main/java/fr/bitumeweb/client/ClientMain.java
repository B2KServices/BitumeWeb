package fr.bitumeweb.client;


import de.mirkosertic.bytecoder.api.Export;
import de.mirkosertic.bytecoder.api.web.Window;

public class ClientMain {
    private static JSWebSocket socket;

    public static void main(String[] args) {
        System.out.println("Hello World !");
        String domain = ((CustomWindow) Window.window()).location().hostname();
        System.out.println(domain);
        socket = JSWebSocket.create("wss://" + domain + ":8443/chat");
        socket.addEventListener("message", aEvent -> {
            String data = Window.window().document().getElementById("log").innerHTML();
            Window.window().document().getElementById("log").innerHTML(data + ((DataEvent) aEvent).data() + "\n");
            System.out.println("Message From Server " + ((DataEvent) aEvent).data());
        });
    }

    @Export("onSubmit")
    public static void onSubmit() {
        socket.send(((CustomButton) Window.window().document().getElementById("message")).value());
        ((CustomButton) Window.window().document().getElementById("message")).value("");
    }

    @Export("onClear")
    public static void effacerLog() {
        Window.window().document().getElementById("log").innerHTML("");
    }
}
