/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.report;

import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.SetResult;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import java.util.Set;

@XmlRootElement()
@XmlAccessorType(XmlAccessType.FIELD)
public class ClientReport extends TlsScanReport {

    // DHE
    private Integer lowestPossibleDheModulusSize;
    private Integer highestPossibleDheModulusSize;

    public ClientReport() {
        super();
    }

    public synchronized List<CompressionMethod> getClientAdvertisedCompressions() {
        ListResult<CompressionMethod> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_ADVERTISED_COMPRESSIONS,
                        CompressionMethod.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<SignatureAndHashAlgorithm>
            getClientAdvertisedSignatureAndHashAlgorithms() {
        ListResult<SignatureAndHashAlgorithm> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                        SignatureAndHashAlgorithm.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized Set<ExtensionType> getClientAdvertisedExtensions() {
        SetResult<ExtensionType> setResult =
                getSetResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS, ExtensionType.class);
        return setResult == null ? null : setResult.getSet();
    }

    public synchronized List<NamedGroup> getClientAdvertisedNamedGroupsList() {
        ListResult<NamedGroup> listResult =
                getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_NAMED_GROUPS, NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<ECPointFormat> getClientAdvertisedPointFormatsList() {
        ListResult<ECPointFormat> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_ADVERTISED_POINTFORMATS, ECPointFormat.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized Integer getLowestPossibleDheModulusSize() {
        return lowestPossibleDheModulusSize;
    }

    public Integer getHighestPossibleDheModulusSize() {
        return highestPossibleDheModulusSize;
    }

    public void setHighestPossibleDheModulusSize(Integer highestPossibleDheModulusSize) {
        this.highestPossibleDheModulusSize = highestPossibleDheModulusSize;
    }

    public synchronized void setLowestPossibleDheModulusSize(Integer lowestPossibleDheModulusSize) {
        this.lowestPossibleDheModulusSize = lowestPossibleDheModulusSize;
    }

    public synchronized List<CipherSuite> getClientAdvertisedCipherSuites() {
        ListResult<CipherSuite> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_ADVERTISED_CIPHERSUITES, CipherSuite.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized void addClientAdvertisedCipherSuites(
            List<CipherSuite> clientAdvertisedCipherSuites) {
        getClientAdvertisedCipherSuites().addAll(clientAdvertisedCipherSuites);
    }

    public synchronized List<NamedGroup> getClientAdvertisedKeyShareNamedGroupsList() {
        ListResult<NamedGroup> listResult =
                getListResult(
                        TlsAnalyzedProperty.CLIENT_ADVERTISED_KEYSHARE_NAMED_GROUPS,
                        NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<String> getClientAdvertisedAlpns() {
        @SuppressWarnings("unchecked")
        ListResult<String> listResult =
                (ListResult<String>) getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_ALPNS);
        return listResult == null ? null : listResult.getList();
    }
}
