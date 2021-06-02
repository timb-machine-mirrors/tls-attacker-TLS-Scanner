/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class StarttlsConfigurationResult extends ProbeResult {

    private TestResult vulnerable;

    private String capabilities;

    public StarttlsConfigurationResult(TestResult vulnerable) {
        this(vulnerable, "");
    }

    public StarttlsConfigurationResult(TestResult vulnerable, String capabilities) {
        super(ProbeType.STARTTLS_CONFIGURATION);
        this.vulnerable = vulnerable;
        this.capabilities = capabilities;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.OFFERS_PLAIN_LOGIN, vulnerable);
        report.setSupportedCapabilities(capabilities);
    }
}
