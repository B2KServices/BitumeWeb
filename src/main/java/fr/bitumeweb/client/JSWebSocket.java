package fr.bitumeweb.client;

import de.mirkosertic.bytecoder.api.Callback;
import de.mirkosertic.bytecoder.api.Import;
import de.mirkosertic.bytecoder.api.OpaqueMethod;
import de.mirkosertic.bytecoder.api.OpaqueProperty;
import de.mirkosertic.bytecoder.api.web.EventTarget;

public abstract class JSWebSocket implements EventTarget {
    @Import(module = "websocket", name = "create")
    public static native JSWebSocket create(String url);

    @OpaqueMethod("send")
    public abstract void send(String data);
}
