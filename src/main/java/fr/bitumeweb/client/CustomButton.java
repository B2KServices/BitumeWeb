package fr.bitumeweb.client;

import de.mirkosertic.bytecoder.api.OpaqueProperty;
import de.mirkosertic.bytecoder.api.web.HTMLButton;

public abstract class CustomButton implements HTMLButton {
    @OpaqueProperty
    public abstract String value();
}
