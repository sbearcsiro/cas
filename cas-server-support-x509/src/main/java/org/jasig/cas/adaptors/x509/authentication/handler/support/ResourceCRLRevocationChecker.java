/*
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.adaptors.x509.authentication.handler.support;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;

import javax.security.auth.x500.X500Principal;
import javax.validation.constraints.Min;
import java.net.URL;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * CRL-based revocation checker that uses one or more CRL resources to fetch
 * local or remote CRL data periodically.  CRL resources should be supplied for
 * the issuers of all certificates (and intervening certificates for certificate
 * chains) that are expected to be presented to {@link X509CredentialsAuthenticationHandler}.
 *
 * @author Marvin S. Addison
 * @since 3.4.7
 *
 */
public class ResourceCRLRevocationChecker extends AbstractCRLRevocationChecker
            implements InitializingBean {

    /** Default refresh interval is 1 hour. */
    public static final int DEFAULT_REFRESH_INTERVAL = 3600;

    /** Executor responsible for refreshing CRL data. */
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    /** CRL refresh interval in seconds. */
    private int refreshInterval = DEFAULT_REFRESH_INTERVAL;

    /** Handles fetching CRL data. */
    private final ResourceCRLFetcher fetcher;

    /** Map of CRL issuer to CRL. */
    private final Map<X500Principal, X509CRL> crlIssuerMap =
            Collections.synchronizedMap(new HashMap<X500Principal, X509CRL>());

    /** Resource CRLs. **/
    private final Resource[] resources;

    /**
     * Creates a new instance using the specified resource for CRL data.
     *
     * @param crl Resource containing CRL data.  MUST NOT be null.
     */
    public ResourceCRLRevocationChecker(final Resource crl) {
        this(new Resource[] {crl});
    }

    /**
     * Creates a new instance using the specified resources for CRL data.
     *
     * @param crls Resources containing CRL data.  MUST NOT be null and MUST have
     * at least one non-null element.
     */
    public ResourceCRLRevocationChecker(final Resource[] crls) {
        this(new ResourceCRLFetcher(), crls);
    }

    /**
     * Instantiates a new Resource cRL revocation checker.
     *
     * @param fetcher the fetcher
     * @param crls the crls
     * @since 4.1
     */
    public ResourceCRLRevocationChecker(final ResourceCRLFetcher fetcher, final Resource[] crls) {
        this.fetcher = fetcher;
        this.resources = crls;
    }


    /**
     * Sets the interval at which CRL data should be reloaded from CRL resources.
     *
     * @param seconds Refresh interval in seconds; MUST be positive integer.
     */
    public void setRefreshInterval(@Min(1) final int seconds) {
        this.refreshInterval = seconds;
    }


    /**
     * {@inheritDoc}
     * Initializes the process that periodically fetches CRL data. */
    @Override
    public void afterPropertiesSet() throws Exception {
        try {
            // Fetch CRL data synchronously and throw exception to abort if any fail
            final Map<URL, X509CRL> results = this.fetcher.fetch(getResources());
            ResourceCRLRevocationChecker.this.addCrls(results);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }

        // Set up the scheduler to fetch periodically to implement refresh
        final Runnable scheduledFetcher = new Runnable() {
            private final Logger logger = LoggerFactory.getLogger(this.getClass());

            @Override
            public void run() {
                try {
                    final Resource[] resources = ResourceCRLRevocationChecker.this.getResources();
                    final Map<URL, X509CRL> results = getFetcher().fetch(resources);
                    ResourceCRLRevocationChecker.this.addCrls(results);
                } catch (final Exception e) {
                    logger.debug(e.getMessage(), e);
                }
            }
        };
        this.scheduler.scheduleAtFixedRate(
                scheduledFetcher, this.refreshInterval, this.refreshInterval, TimeUnit.SECONDS);
    }

    /**
     * Add fetches crls to the map.
     *
     * @param results the results
     */
    private void addCrls(final Map<URL, X509CRL> results) {
        final Set<Map.Entry<URL, X509CRL>> keys = results.entrySet();
        final Iterator<Map.Entry<URL, X509CRL>> it = keys.iterator();
        while (it.hasNext()) {
            final Map.Entry<URL, X509CRL> entry = it.next();
            addCRL(entry.getKey(), entry.getValue());
        }
    }

    /**
     * @return Returns the CRL fetcher component.
     */
    protected CRLFetcher getFetcher() {
        return this.fetcher;
    }

    protected Resource[] getResources() {
        return this.resources;
    }
    /**
     * {@inheritDoc}
     * <p>
     * Id is always ignored and the entry is put int the CRL
     * map based on it {@link X509CRL#getIssuerX500Principal()}.
     * </p>
     */
    @Override
    protected boolean addCRL(final Object id, final X509CRL crl) {
        final X500Principal issuer = crl.getIssuerX500Principal();
        logger.debug("Adding CRL for issuer {}", issuer);
        this.crlIssuerMap.put(issuer, crl);
        return this.crlIssuerMap.containsKey(issuer);
    }

    /**
     * {@inheritDoc}
     * @see AbstractCRLRevocationChecker#getCRL(X509Certificate)
     */
    @Override
    protected X509CRL getCRL(final X509Certificate cert) {
        return this.crlIssuerMap.get(cert.getIssuerX500Principal());
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        this.scheduler.shutdown();
    }

}
