package world.gfi.updatecacert;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class RecordingX509TrustManager implements X509TrustManager {
    public static class Check {
        private CertificateException exception;
        private String authType;
        private X509Certificate[] chain;

        public Check(X509Certificate[] chain, String authType) {
            this.chain = chain;
            this.authType = authType;
        }

        public Check(X509Certificate[] chain, String authType, CertificateException exception) {
            this.chain = chain;
            this.authType = authType;
            this.exception = exception;
        }

        public CertificateException getException() {
            return exception;
        }

        public String getAuthType() {
            return authType;
        }

        public X509Certificate[] getChain() {
            return chain;
        }
    }

    private final X509TrustManager tm;
    private final List<Check> clientChecks = new ArrayList<>();
    private final List<Check> serverChecks = new ArrayList<>();


    public RecordingX509TrustManager(X509TrustManager tm) {
        this.tm = tm;
    }

    public X509Certificate[] getAcceptedIssuers() {
        return tm.getAcceptedIssuers();
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        try {
            tm.checkClientTrusted(chain, authType);
            this.clientChecks.add(new Check(chain, authType));
        } catch (CertificateException e) {
            this.clientChecks.add(new Check(chain, authType, e));
            throw e;
        }
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        try {
            tm.checkServerTrusted(chain, authType);
            this.serverChecks.add(new Check(chain, authType));
        } catch (CertificateException e) {
            this.serverChecks.add(new Check(chain, authType, e));
            throw e;
        }
    }

    public X509Certificate[] getLastServerChain() {
        return this.serverChecks.get(this.serverChecks.size() - 1).getChain();
    }

    public List<Check> getServerChecks() {
        return serverChecks;
    }

    public List<Check> getClientChecks() {
        return clientChecks;
    }
}
