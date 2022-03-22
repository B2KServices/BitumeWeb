package fr.bitumeweb.client;

import de.mirkosertic.bytecoder.api.OpaqueProperty;
import de.mirkosertic.bytecoder.api.web.Event;

public abstract class DataEvent implements Event {
    @Override
    public String type() {
        return "MessageEvent";
    }

    @Override
    public void preventDefault() {
        //this is impossible to prevent, at least i think
    }

    @OpaqueProperty
    public abstract String data();
}
