package world.gfi.updatecacert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Option;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileSystems;
import java.nio.file.PathMatcher;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;


public class UpdateCaCertificates implements Callable<Void> {
    private Logger log = LoggerFactory.getLogger(UpdateCaCertificates.class);

    @Option(names = {"-h", "--host"}, defaultValue = "google.com",
            description = "Host to check. " +
                    "This will intercept SSL certificates chain returned by this host. If chain is not trusted, " +
                    "it will add the last certificate in chain to trusted store, or the one specified by index option." + 
                    "(default: google.com)")
    private String host = "google.com";

    @Option(names = {"-p", "--port"}, defaultValue = "443", description = "TCP port of the host to check. (default: 443)")
    private Integer port = 443;

    @Option(names = {"-i", "--index"}, description = "Index of the certificate to add. (default: Last certificate index in certificate chain)")
    private Integer index;

    @Option(names = {"-d", "--directory"}, description = "Directory containing .crt files to update.")
    private List<File> directory;

    @Option(names = {"-g", "--glob"}, description = "Glob filter of certificate files to load.")
    private String glob;

    @Option(names = {"-f", "--file"}, description = "File containing certificate file (PEM).")
    private List<File> file;

    public static void main(String[] args) {
        CommandLine.call(new UpdateCaCertificates(), args);
    }

    public Void call() throws Exception {
        String p = System.getProperty("javax.net.ssl.trustStorePassword") != null ? System.getProperty("javax.net.ssl.trustStorePassword") : "changeit";
        char[] passphrase = p.toCharArray();

        File trustStoreFile = Utils.getTrustStoreFile();

        log.debug("Loading Trust KeyStore {}", trustStoreFile);

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream in = new FileInputStream(trustStoreFile);
        try {
            keyStore.load(in, passphrase);
        } finally {
            in.close();
        }

        PathMatcher pathMatcher = glob == null ? null : FileSystems.getDefault().getPathMatcher("glob:" + glob);

        List<X509Certificate> certs = new ArrayList<>();

        if (this.file == null && this.directory == null) {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            RecordingX509TrustManager tm = new RecordingX509TrustManager(defaultTrustManager);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{tm}, null);
            SSLSocketFactory factory = context.getSocketFactory();

            log.debug("Opening connection to {} : {} ...", host, port);

            SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(10000);
            try {
                log.debug("Starting SSL handshake...");

                socket.startHandshake();
                socket.close();

                log.info("Certificate chain is already trusted.");
            } catch (SSLException e) {
                log.warn("Certificate chain is NOT trusted.");
                log.warn(e.getMessage());

                X509Certificate[] chain = tm.getLastServerChain();
                if (chain == null) {
                    log.error("Could not obtain server certificate chain");
                    return null;
                }

                log.info("Certificate chain has {} certificate(s).", chain.length);

                if (chain.length > 1 && this.index == null || chain.length >= this.index) {
                    this.index = chain.length - 1;
                }

                certs.add(chain[this.index]);
            }

            return null;
        }

        if (this.file != null) {
            for (File file : this.file) {
                if (shouldUpdate(file, pathMatcher)) {
                    X509Certificate cert = this.loadCrt(file);
                    certs.add(cert);
                }
            }
        }

        if (this.directory != null) {
            for (File directory : this.directory) {
                for (File file : directory.listFiles()) {
                    if (shouldUpdate(file, pathMatcher)) {
                        X509Certificate cert = this.loadCrt(file);
                        certs.add(cert);
                    }
                }
            }
        }

        log.info("{} certificates to update", certs.size());

        for (X509Certificate cert : certs) {
            log.info(String.valueOf(cert));

            String alias = updateCaCertificate(keyStore, passphrase, trustStoreFile, cert);

            log.info("Certificate added to keystore {} using alias '{}'", trustStoreFile, alias);
        }

        return null;
    }

    private boolean shouldUpdate(File file, PathMatcher pathMatcher) {
        return file.isFile() && pathMatcher != null && pathMatcher.matches(FileSystems.getDefault().getPath(file.toString()));
    }

    private String updateCaCertificate(KeyStore keyStore, char[] password, File trustStoreFile, X509Certificate cert)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String alias = cert.getSubjectDN().getName();

        keyStore.setCertificateEntry(alias, cert);
        OutputStream out = new FileOutputStream(trustStoreFile);
        try {
            keyStore.store(out, password);
        } finally {
            out.close();
        }

        return alias;
    }

    private X509Certificate loadCrt(File certificateFile) throws IOException, CertificateException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(certificateFile);
        try {
            X509Certificate cert = (X509Certificate) fact.generateCertificate(is);
            return cert;
        } finally {
            is.close();
        }
    }
}

