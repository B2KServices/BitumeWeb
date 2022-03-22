package fr.bitumeweb.client;

import de.mirkosertic.bytecoder.api.OpaqueProperty;
import de.mirkosertic.bytecoder.api.web.Window;

public abstract class CustomWindow extends Window {
    @OpaqueProperty
    public abstract Location location();
}
