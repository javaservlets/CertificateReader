package com.example.certificate;


import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.inject.Inject;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.servlet.http.HttpServletRequest;

import com.google.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;

@Node.Metadata(outcomeProvider = CertificateReader.MyOutcomeProvider.class, configClass = CertificateReader.Config.class)


public class CertificateReader implements Node {
    private static final String BUNDLE = "com/example/certificate/CertificateReader";
    private final Config config;
    private final static String DEBUG_FILE = "CertificateReader";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);
    private final Logger logger = LoggerFactory.getLogger(CertificateReader.class);

    private String readCert(TreeContext context) {
        String c_name = null;
        try {
            final HttpServletRequest servlet_request = context.request.servletRequest;

            X509Certificate[] certs = (X509Certificate[]) servlet_request.getAttribute("javax.servlet.request.X509Certificate");
            if (certs.length < 1) {// Check that a certificate was obtained
                log("SSL not client authenticated");
                return c_name;
            }
            X509Certificate principalCert = certs[0];

            Principal principal = principalCert.getSubjectDN();// Get the Distinguished Name from the certificate
            log("readCert got dn: " + principal.getName());

            String dn = principalCert.getSubjectX500Principal().getName();
            LdapName ldapDN = new LdapName(dn);
            for (Rdn rdn : ldapDN.getRdns()) {
                //System.out.println(rdn.getType() + " -> " + rdn.getValue());
                if (rdn.getType().equals("CN")) c_name = (String) rdn.getValue();
            }
            log("readCert got cn: " + c_name);
        } catch (Exception e) {
            log("error on getting request");
        }

        return c_name;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        String c_name = readCert(context);
        Action action = null ;

        if (c_name.equals(null)) {
            action = goTo(MyOutcome.EMPTY).build();
        } else if (c_name.length() > 1) {
            action = goTo(MyOutcome.FOUND).replaceSharedState(context.sharedState
                    .put("device_id", c_name)) //  param is common_name parsed out of x509 cert
                    .build();
        } else {
            action = goTo(MyOutcome.UNKNOWN).build(); //not sure how we'd get here, but lets trap anyway
        }
        return action;
    }

    public interface Config {
        @Attribute(order = 100)
        default String fieldName() {
            return "common_name";
        } //todo use bundle if this is going to ever b read

//        @Attribute(order = 200)
//        default String password() {
//            return "";
//        }
//
//        @Attribute(order = 300)
//        default String misc() {
//            return "misc";
//        }
    }

    @Inject
    public CertificateReader(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        //rj this.realm = realm;
    }

    public static class MyOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            return ImmutableList.of(
                    new Outcome(MyOutcome.FOUND.name(), "Found"),
                    new Outcome(MyOutcome.UNKNOWN.name(), "Not Found"),
                    new Outcome(MyOutcome.EMPTY.name(), "Empty"));
        }
    }

    private Action.ActionBuilder goTo(MyOutcome outcome) {
        return Action.goTo(outcome.name());
    }

    public enum MyOutcome {
        /**
         * Successful parsing of cert for a dev id.
         */
        FOUND,
        /**
         * no dev id found in cert
         */
        EMPTY,
        /**
         * no cert found
         */
        UNKNOWN,
    }

    public void log(String str) {
        debug.error("\r\n           " + str);
        System.out.println("+++    CertificateReader:" + str);
    }


    private void doPassword() {
        //    private final static String KEYSTORE = "/security/client.jks";
        //    private final static String KEYSTORE_PASSWORD = "secret";
        //    private final static String KEYSTORE_TYPE = "JKS";
        //    private final static String TRUSTSTORE = "/security/certificates.jks";
        //    private final static String TRUSTSTORE_PASSWORD = "secret";
        //    private final static String TRUSTSTORE_TYPE = "JKS";
        //

        try {
            //            KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            //            FileInputStream keystoreInput = new FileInputStream(new File(KEYSTORE));
            //            keystore.load(keystoreInput, KEYSTORE_PASSWORD.toCharArray());
            //            KeyStore truststore = KeyStore.getInstance(TRUSTSTORE_TYPE);
            //            FileInputStream truststoreIs = new FileInputStream(new File(TRUSTSTORE));
            //            truststore.load(truststoreIs, TRUSTSTORE_PASSWORD.toCharArray());
            //            SSLSocketFactory socketFactory = new SSLSocketFactory(keystore, KEYSTORE_PASSWORD, truststore);
            //            Scheme scheme = new Scheme("https", 8543, socketFactory);
            //            SchemeRegistry registry = new SchemeRegistry();
            //            registry.register(scheme);
            //            ClientConnectionManager ccm = new PoolingClientConnectionManager(registry);
            //            httpclient = new DefaultHttpClient(ccm);
            //            HttpResponse response = null;
            //            HttpGet httpget = new HttpGet("https://iot.freng.org:8443");
            //            response = httpclient.execute(httpget);
        } catch (Exception e) {
            log("doPassword e: " + e);
        }
    }
}
