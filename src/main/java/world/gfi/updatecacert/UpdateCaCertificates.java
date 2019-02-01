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
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;


public class UpdateCaCertificates implements Callable<Void> {
    private Logger log = LoggerFactory.getLogger(UpdateCaCertificates.class);

    @Option(names = {"-h", "--host"}, defaultValue = "google.com", description = "Host to check. This will intercept all SSL certificates required by this host.")
    private String host = "google.com";

    @Option(names = {"-p", "--port"}, defaultValue = "443", description = "TCP port of the host to check.")
    private Integer port = 443;

    @Option(names = {"-i", "--index"}, description = "Index of the certificate to add.")
    private Integer index;

    @Option(names = {"-a", "--alias"}, description = "TCP port of the host to check.")
    private String alias;

    @Option(names = {"-d", "--directory"}, description = "Directory containing .crt files to update.")
    private String directory;
    
    @Option(names = {"-f", "--file"}, description = "File containing certificate file (PEM).")
    private String file;

    public static void main(String[] args) {
        CommandLine.call(new UpdateCaCertificates(), args);
    }

    public Void call() throws Exception {
        String p = System.getProperty("javax.net.ssl.trustStorePassword") != null ? System.getProperty("javax.net.ssl.trustStorePassword") : "changeit";
        char[] passphrase = p.toCharArray();

        File trustStoreFile = Utils.getTrustStoreFile();

        log.debug("Loading Trust KeyStore " + trustStoreFile + "...");

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream in = new FileInputStream(trustStoreFile);
        try {
            keystore.load(in, passphrase);
        } finally {
            in.close();
        }

        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keystore);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        RecordingX509TrustManager tm = new RecordingX509TrustManager(defaultTrustManager);
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        log.debug("Opening connection to " + host + ":" + port + "...");
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(10000);
        try {
            log.debug("Starting SSL handshake...");
            socket.startHandshake();
            socket.close();
            log.info("Certificate chain is already trusted.");
            return null;
        } catch (SSLException e) {
            log.warn("Certificate chain is NOT trusted.");
            log.warn(e.getMessage());
        }

        X509Certificate[] chain = tm.getLastServerChain();
        if (chain == null) {
            log.error("Could not obtain server certificate chain");
            return null;
        }

        log.info("Certificate chain has " + chain.length + " certificate(s).");

        if (chain.length > 1 && this.index == null || chain.length >= this.index) {
            this.index = chain.length - 1;
        }

        X509Certificate cert = chain[this.index];
        

        String alias = this.alias;
        if (alias == null) {
            alias = cert.getSubjectDN().getName();
        }

        keystore.setCertificateEntry(alias, cert);

        OutputStream out = new FileOutputStream(trustStoreFile);
        try {
            keystore.store(out, passphrase);
        } finally {
            out.close();
        }

        log.info(String.valueOf(cert));
        log.info("Added certificate to keystore " + trustStoreFile + " using alias '" + alias + "'");

        return null;
    }
}

