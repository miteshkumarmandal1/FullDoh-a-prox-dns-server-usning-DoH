/*
 * FullDoH - Local DNS-over-HTTPS (DoH) Proxy
 *
 * An educational Java server that translates standard DNS queries
 * into DNS-over-HTTPS (DoH) requests and converts the responses back
 * into DNS format for local clients.
 *
 * This project is intended for learning and research purposes only.
 * It demonstrates DNS packet parsing, HTTPS transport, and protocol
 * translation without attempting to bypass network security controls.
 *
 * Copyright © 2026 FullDoH Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
/**
 * FullDoHBinaryServer
 *
 * - UDP + TCP DNS server on port 53
 * - Uses Google DoH binary API (RFC8484): POST https://dns.google/dns-query (application/dns-message)
 * - Forwards raw wire-format DNS query and returns raw wire-format DNS response
 * - UDP responses > 512 are truncated (TC bit set)
 * - Returns SERVFAIL (including original question) on DoH failure
 *
 * Notes:
 * - Run as Administrator/root to bind port 53.
 * - This is a pragmatic resolver/proxy — not a full authoritative server implementation.
 */

//Kept all code in one file, so that anyone can run it easily using command prompt with one command java FullDoHBinaryServer.java
public class FullDoHBinaryServer {

    private static final int PORT = 53;
    private static final int UDP_BUF_SIZE = 4096;
    private static final String DOH_URL = "https://dns.google/dns-query";
    private static final int DOH_TIMEOUT_MS = 4000;
    private static final int THREADS = 8;
    private static final boolean LOG = true;

    private static final ExecutorService EXEC = Executors.newFixedThreadPool(THREADS);

    public static void main(String[] args) throws Exception {
        log("Starting FullDoHBinaryServer on port " + PORT);

        // UDP listener
        Thread udpThread = new Thread(() -> {
            try (DatagramSocket ds = new DatagramSocket(PORT)) {
                ds.setReceiveBufferSize(UDP_BUF_SIZE);
                log("UDP socket bound on " + PORT);
                byte[] buf = new byte[UDP_BUF_SIZE];
                while (true) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    ds.receive(p);
                    byte[] req = Arrays.copyOf(p.getData(), p.getLength());
                    InetAddress clientAddr = p.getAddress();
                    int clientPort = p.getPort();
                    EXEC.submit(() -> handleUdpRequest(ds, clientAddr, clientPort, req));
                }
            } catch (BindException be) {
                log("ERROR: Bind failed on port " + PORT + ". Are you running as admin/root? " + be.getMessage());
            } catch (Exception e) {
                log("UDP listener error: " + e.getMessage());
                e.printStackTrace();
            }
        }, "udp-listener");
        udpThread.setDaemon(false);
        udpThread.start();

        // TCP listener
        Thread tcpThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(PORT)) {
                log("TCP socket bound on " + PORT);
                while (true) {
                    Socket s = ss.accept();
                    EXEC.submit(() -> handleTcpConnection(s));
                }
            } catch (BindException be) {
                log("ERROR: Bind failed on port " + PORT + ". Are you running as admin/root? " + be.getMessage());
            } catch (Exception e) {
                log("TCP listener error: " + e.getMessage());
                e.printStackTrace();
            }
        }, "tcp-listener");
        tcpThread.setDaemon(false);
        tcpThread.start();
    }

    // --------------------
    // UDP handler
    // --------------------
    private static void handleUdpRequest(DatagramSocket serverSocket, InetAddress clientAddr, int clientPort, byte[] request) {
        try {
            String qname = tryExtractDomainSafe(request);
            int qtype = tryExtractQTypeSafe(request);
            logf("UDP Query from %s:%d ? %s type=%d", clientAddr.getHostAddress(), clientPort, qname == null ? "<unknown>" : qname, qtype);

            byte[] dohResp = dohBinaryQuery(request); // raw wire-format response

            if (dohResp == null || dohResp.length == 0) {
                log("DoH failed - returning SERVFAIL to " + clientAddr.getHostAddress() + ":" + clientPort);
                byte[] serv = buildServfailWithQuestion(request);
                DatagramPacket respPacket = new DatagramPacket(serv, serv.length, clientAddr, clientPort);
                serverSocket.send(respPacket);
                log("Sent SERVFAIL UDP response (" + serv.length + " bytes) to " + clientAddr.getHostAddress() + ":" + clientPort);
                return;
            }

            // If response larger than 512 bytes, truncate and set TC bit
            if (dohResp.length > 512) {
                byte[] truncated = Arrays.copyOf(dohResp, 512);
                // set TC bit in header: use mask 0x02 on header byte 2 (flags high)
                truncated[2] = (byte) (truncated[2] | 0x02);
                DatagramPacket respPacket = new DatagramPacket(truncated, truncated.length, clientAddr, clientPort);
                serverSocket.send(respPacket);
                log("Sent UDP TRUNCATED response to " + clientAddr.getHostAddress() + ":" + clientPort + " (" + truncated.length + " bytes)");
            } else {
                DatagramPacket respPacket = new DatagramPacket(dohResp, dohResp.length, clientAddr, clientPort);
                serverSocket.send(respPacket);
                log("Sent UDP response to " + clientAddr.getHostAddress() + ":" + clientPort + " (" + dohResp.length + " bytes)");
            }

        } catch (Exception e) {
            log("handleUdpRequest error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // --------------------
    // TCP handler
    // --------------------
    private static void handleTcpConnection(Socket s) {
        try (Socket sock = s;
             InputStream in = sock.getInputStream();
             OutputStream out = sock.getOutputStream()) {

            // Read 2-byte length prefix
            byte[] lenBuf = new byte[2];
            if (in.read(lenBuf) != 2) return;
            int len = ((lenBuf[0] & 0xFF) << 8) | (lenBuf[1] & 0xFF);
            if (len <= 0 || len > 65535) return;

            byte[] req = new byte[len];
            int read = 0;
            while (read < len) {
                int r = in.read(req, read, len - read);
                if (r < 0) throw new EOFException("Unexpected EOF on TCP read");
                read += r;
            }

            String qname = tryExtractDomainSafe(req);
            int qtype = tryExtractQTypeSafe(req);
            logf("TCP Query from %s:%d ? %s type=%d", sock.getInetAddress().getHostAddress(), sock.getPort(), qname == null ? "<unknown>" : qname, qtype);

            byte[] dohResp = dohBinaryQuery(req);

            if (dohResp == null || dohResp.length == 0) {
                log("DoH failed for TCP - returning SERVFAIL to " + sock.getInetAddress().getHostAddress());
                byte[] serv = buildServfailWithQuestion(req);
                byte[] outLen = new byte[]{(byte) ((serv.length >> 8) & 0xFF), (byte) (serv.length & 0xFF)};
                try {
                    out.write(outLen);
                    out.write(serv);
                    out.flush();
                    log("Sent TCP SERVFAIL to " + sock.getInetAddress().getHostAddress());
                } catch (SocketException se) {
                    log("Client aborted TCP connection (normal): " + se.getMessage());
                }
                return;
            }

            // send length prefixed full response
            byte[] outLen = new byte[]{(byte) ((dohResp.length >> 8) & 0xFF), (byte) (dohResp.length & 0xFF)};
            try {
                out.write(outLen);
                out.write(dohResp);
                out.flush();
                log("Sent TCP response to " + sock.getInetAddress().getHostAddress() + " (" + dohResp.length + " bytes)");
            } catch (SocketException se) {
                log("Client aborted TCP connection (normal): " + se.getMessage());
            } catch (IOException ioe) {
                log("TCP write error: " + ioe.getMessage());
            }

        } catch (Exception e) {
            log("TCP connection error: " + e.getMessage());
            if (!(e instanceof SocketException)) e.printStackTrace();
        }
    }

    // --------------------
    // DoH binary exchange (POST application/dns-message)
    // --------------------
    private static byte[] dohBinaryQuery(byte[] query) {
        HttpsURLConnection conn = null;
        try {
            URL url = new URL(DOH_URL);
            conn = (HttpsURLConnection) url.openConnection();
            conn.setConnectTimeout(DOH_TIMEOUT_MS);
            conn.setReadTimeout(DOH_TIMEOUT_MS);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/dns-message");
            conn.setRequestProperty("Accept", "application/dns-message");
            conn.setInstanceFollowRedirects(false);

            // send raw wire-format query
            try (OutputStream os = conn.getOutputStream()) {
                os.write(query);
                os.flush();
            }

            int code = conn.getResponseCode();
            if (code != 200) {
                log("DoH non-200: " + code + " from " + DOH_URL);
                // try to read any error body (optional)
                try { String err = readAll(conn.getErrorStream()); if (err != null && !err.isEmpty()) log("DoH error body: " + err); } catch (Exception ignored) {}
                return null;
            }

            try (InputStream is = conn.getInputStream();
                 ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
                byte[] buf = new byte[4096];
                int r;
                while ((r = is.read(buf)) > 0) bout.write(buf, 0, r);
                return bout.toByteArray();
            }

        } catch (SocketTimeoutException ste) {
            log("DoH timeout to " + DOH_URL);
            return null;
        } catch (Exception e) {
            log("DoH error -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // Build a SERVFAIL response that includes the original question bytes (so clients accept it).
    // If we cannot parse question, return a minimal 12-byte header with SERVFAIL (less ideal).
    private static byte[] buildServfailWithQuestion(byte[] request) {
        try {
            if (request == null || request.length < 12) {
                // minimal header: copy what we can
                byte[] h = new byte[12];
                Arrays.fill(h, (byte)0);
                return h;
            }
            // copy ID and original header
            byte[] header = Arrays.copyOfRange(request, 0, 12);
            // set QR=1 and copy RD bit from original header[2]; set RCODE=2 (SERVFAIL) and RA=1
            header[2] = (byte) (0x80 | (request[2] & 0x01)); // QR=1 and copy RD
            header[3] = (byte) 0x82; // RA=1 and RCODE=2 (SERVFAIL)
            // set ancount=0
            header[6] = 0; header[7] = 0;
            // preserve qdcount from original request (already in header[4..5])
            // find end of question section
            int qend = findQuestionEnd(request, 12);
            if (qend <= 12) qend = Math.min(request.length, 12 + 5); // fallback
            byte[] questionBytes = Arrays.copyOfRange(request, 12, Math.min(qend, request.length));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(header);
            out.write(questionBytes);
            // No answers
            return out.toByteArray();
        } catch (Exception e) {
            // fallback minimal servfail header
            byte[] h = new byte[12];
            Arrays.fill(h, (byte)0);
            return h;
        }
    }

    // Find end position of question section (returns index after QTYPE+QCLASS)
    private static int findQuestionEnd(byte[] data, int startPos) {
        int pos = startPos;
        try {
            int max = data.length;
            // skip QNAME
            while (pos < max && data[pos] != 0) {
                int len = data[pos] & 0xFF;
                if (len == 0) { pos++; break; }
                pos += 1 + len;
            }
            if (pos < max && data[pos] == 0) pos++; // skip terminating 0
            // skip QTYPE + QCLASS (4 bytes)
            if (pos + 4 <= max) pos += 4;
            return pos;
        } catch (Exception e) {
            return startPos;
        }
    }

    // Try to extract question domain string for logging (best-effort)
    private static String tryExtractDomainSafe(byte[] req) {
        try {
            if (req == null || req.length < 13) return null;
            int pos = 12;
            StringBuilder sb = new StringBuilder();
            int max = req.length;
            while (pos < max) {
                int len = req[pos++] & 0xFF;
                if (len == 0) break;
                if (len > 63 || pos + len > max) break;
                sb.append(new String(req, pos, len));
                pos += len;
                sb.append('.');
            }
            if (sb.length() == 0) return "";
            if (sb.charAt(sb.length()-1) == '.') sb.setLength(sb.length()-1);
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // Try to extract qtype (best-effort)
    private static int tryExtractQTypeSafe(byte[] req) {
        try {
            if (req == null || req.length < 16) return -1;
            int pos = findQuestionEnd(req, 12);
            // QTYPE is two bytes before QCLASS; but easier: go to end of qname then read two bytes QTYPE at pos-4
            // We'll reparse:
            pos = 12;
            int max = req.length;
            while (pos < max) {
                int len = req[pos++] & 0xFF;
                if (len == 0) break;
                pos += len;
            }
            if (pos + 1 >= max) return -1;
            int qtype = ((req[pos] & 0xFF) << 8) | (req[pos+1] & 0xFF);
            return qtype;
        } catch (Exception e) {
            return -1;
        }
    }

    // --------------------
    // Utilities
    // --------------------
    private static String readAll(InputStream in) throws IOException {
        if (in == null) return null;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
            StringBuilder sb = new StringBuilder();
            String l;
            while ((l = br.readLine()) != null) sb.append(l).append('\n');
            return sb.toString();
        }
    }

    private static void log(String s) { if (LOG) System.out.println("[" + Instant.now() + "] " + s); }
    private static void logf(String fmt, Object... args) { if (LOG) System.out.println("[" + Instant.now() + "] " + String.format(fmt, args)); }
}


