/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.PossibleSecret;
import java.util.List;

public class TicketTls12 implements Ticket {

    private byte[] ticketBytes;
    private byte[] masterSecret;
    private List<PossibleSecret> possibleSecrets;

    public TicketTls12(
            byte[] ticketBytes, byte[] masterSecret, List<PossibleSecret> possibleSecrets) {
        this.ticketBytes = ticketBytes;
        this.masterSecret = masterSecret;
        this.possibleSecrets = possibleSecrets;
    }

    public TicketTls12(TicketTls12 toCopy) {
        this(toCopy.ticketBytes, toCopy.masterSecret, toCopy.possibleSecrets);
    }

    @Override
    public void applyTo(Config config) {
        config.setTlsSessionTicket(ticketBytes);
        config.setDefaultMasterSecret(masterSecret);
    }

    @Override
    public void setTicketBytes(byte[] ticketBytes) {
        this.ticketBytes = ticketBytes;
    }

    @Override
    public byte[] getTicketBytesOriginal() {
        return ticketBytes;
    }

    @Override
    public Ticket copy() {
        return new TicketTls12(this);
    }

    @Override
    public List<PossibleSecret> getPossibleSecrets() {
        return possibleSecrets;
    }

    @Override
    public String toString() {
        return ArrayConverter.bytesToHexString(ticketBytes, false, false);
    }
}
