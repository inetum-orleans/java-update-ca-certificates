package world.gfi.updatecacert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Option;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileSystems;
import java.nio.file.PathMatcher;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;


public class UpdateCaCertificates implements Callable<Integer> {
    private Logger log = LoggerFactory.getLogger(UpdateCaCertificates.class);

    @Option(names = {"-h", "--host"}, defaultValue = "stackexchange.com",
            description = "Host to check. " +
                    "This will intercept SSL certificates chain returned by this host. If chain is not trusted, " +
                    "it will add the last certificate in chain to trusted store, or the one specified by index option." +
                    "(default: stackoverflow.com)")
    private String host = "stackoverflow.com";

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

    @Option(names = {"-t", "--truststore"}, description = "Truststore file to used.")
    private File truststore;

    public static void main(String[] args) {
        Integer ret = CommandLine.call(new UpdateCaCertificates(), args);
        if (ret != null) {
            System.exit(ret);
        }
    }

    public Integer call() throws Exception {
        String p = System.getProperty("javax.net.ssl.trustStorePassword") != null ? System.getProperty("javax.net.ssl.trustStorePassword") : "changeit";
        char[] passphrase = p.toCharArray();

        File trustStoreFile = null;
        if (this.truststore != null) {
            trustStoreFile = this.truststore;
        } else {
            trustStoreFile = Utils.getTrustStoreFile();
        }

        log.debug("Loading Trust KeyStore {}", trustStoreFile);

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream in = new FileInputStream(trustStoreFile);
        try {
            keyStore.load(in, passphrase);
        } finally {
            in.close();
        }

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

                return null;
            } catch (SSLHandshakeException e) {
                log.warn("Certificate chain is NOT trusted.");
                log.warn(e.getMessage());

                X509Certificate[] chain = tm.getLastServerChain();
                if (chain == null) {
                    log.error("Could not obtain server certificate chain");
                    return 1;
                }

                log.info("Certificate chain has {} certificate(s).", chain.length);

                if (chain.length >= 1 && (this.index == null || chain.length >= this.index)) {
                    this.index = chain.length - 1;
                }

                certs.add(chain[this.index]);
            }
        }

        PathMatcher pathMatcher = glob == null ? null : FileSystems.getDefault().getPathMatcher("glob:" + glob);

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
            updateCaCertificate(keyStore, passphrase, trustStoreFile, cert);
        }

        return null;
    }

    private boolean shouldUpdate(File file, PathMatcher pathMatcher) {
        return file.isFile() && (pathMatcher == null || pathMatcher.matches(FileSystems.getDefault().getPath(file.toString())));
    }

    private String updateCaCertificate(KeyStore keyStore, char[] password, File trustStoreFile, X509Certificate cert)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String alias = cert.getSubjectDN().getName();

        Certificate existingCert = keyStore.getCertificate(alias);
        if (existingCert != null && existingCert.equals(cert)) {
            log.info("Certificate already exists in keystore {} using alias '{}'", trustStoreFile, alias);
        } else {
            keyStore.setCertificateEntry(alias, cert);
            boolean writable = trustStoreFile.canWrite();
            boolean shouldRestoreReadonly = false;
            if (!writable) {
                writable = trustStoreFile.setWritable(true);
                shouldRestoreReadonly = true;
            }

            if (!writable) {
                log.error("Truststore file is not writable. You should adjust file permissions for " + trustStoreFile + " to allow current user write access.");
            }

            OutputStream out = new FileOutputStream(trustStoreFile);
            try {
                keyStore.store(out, password);
            } catch (FileNotFoundException e) {
                log.error("Truststore file is not writable. You should adjust file permissions for " + trustStoreFile + " to allow current user write access.");
                throw e;
            } finally {
                out.close();
                if (shouldRestoreReadonly) {
                    trustStoreFile.setWritable(false);
                }
            }

            log.info("Certificate added to keystore {} using alias '{}'", trustStoreFile, alias);
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

