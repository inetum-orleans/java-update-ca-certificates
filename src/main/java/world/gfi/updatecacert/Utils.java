package world.gfi.updatecacert;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public final class Utils {
    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

    public static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }

    public static File getTrustStoreFile() {
        char sep = File.separatorChar;

        String[] directories = new String[]{
                System.getProperty("java.home") + sep + "lib" + sep + "security",
                System.getProperty("java.home") + sep + "jre" + sep + "lib" + sep + "security"
        };

        String[] filenames = new String[]{
                "jssecacerts",
                "cacerts"
        };

        List<File> files = new ArrayList<>();
        if (System.getProperty("javax.net.ssl.trustStore") != null) {
            files.add(new File(System.getProperty("javax.net.ssl.trustStore")));
        }

        for (String directory : directories) {
            for (String filename : filenames) {
                files.add(new File(directory, filename));
            }
        }

        for (File file : files) {
            if (file.exists()) {
                return file;
            }
        }

        throw new IllegalStateException("No trustStore file was found. Use -t/--truststore option or define javax.net.ssl.trustStore system property.");
    }
}
