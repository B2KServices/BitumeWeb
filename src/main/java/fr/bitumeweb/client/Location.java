package fr.bitumeweb.client;

import de.mirkosertic.bytecoder.api.OpaqueProperty;
import de.mirkosertic.bytecoder.api.OpaqueReferenceType;

public abstract class Location implements OpaqueReferenceType {
    @OpaqueProperty
    public abstract String hostname();
}
