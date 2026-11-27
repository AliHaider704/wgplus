package org.telegram.wgplus.module;

import android.content.Context;
import android.os.SystemClock;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import wgbridge.Wgbridge;

/**
 * Active network probing extracted from {@link WgHealthAndContinuity}: endpoint pre-resolution,
 * concurrent profile latency ranking, path MTU discovery, and SOCKS5 route/VoIP verification.
 */
final class WgTunnelProber {

    private static final SecureRandom PROBE_RAND = new SecureRandom();

    private WgTunnelProber() {
    }

    static String preResolveEndpoint(String rawEndpoint) {
        String ep = WireGuardManager.safeTrim(rawEndpoint);
        if (ep.isEmpty() || ep.startsWith("[")) {
            return ep;
        }
        int lastColon = ep.lastIndexOf(':');
        if (lastColon <= 0 || lastColon == ep.length() - 1) {
            return ep;
        }
        String host = ep.substring(0, lastColon).trim();
        String port = ep.substring(lastColon + 1).trim();
        if (host.indexOf(':') >= 0) {
            return ep;
        }
        try {
            InetAddress[] addrs = InetAddress.getAllByName(host);
            if (addrs != null && addrs.length > 0) {
                InetAddress chosen = addrs[0];
                for (InetAddress candidate : addrs) {
                    if (candidate instanceof Inet4Address) {
                        chosen = candidate;
                        break;
                    }
                }
                String ip = chosen.getHostAddress();
                if (ip != null && !ip.isEmpty()) {
                    return chosen instanceof Inet4Address ? (ip + ":" + port) : ("[" + ip + "]:" + port);
                }
            }
        } catch (Throwable t) {
            Log.w(WireGuardManager.TAG, "Java DNS pre-resolve fallback to Go resolver for " + host + ": " + t.getMessage());
        }
        return ep;
    }

    /**
     * Concurrently probes all configured profiles via isolated cryptographic WireGuard / AmneziaWG handshakes,
     * selects the fastest responder, and live-switches if currently connected to a slower server.
     */
    static WireGuardManager.PingWinnerResult pingAllProfilesAndSelectFastest(
            final Context context,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader
    ) throws Exception {
        NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
        final List<WireGuardManager.TunnelConfig> profiles = WireGuardManager.loadProfiles(context);
        final List<WireGuardManager.TunnelConfig> configured = new ArrayList<>();
        for (WireGuardManager.TunnelConfig p : profiles) {
            if (p.hasPeerConfigured()) {
                configured.add(p);
            }
        }
        if (configured.isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.MISSING_ENDPOINT);
        }

        final boolean useDoH = WireGuardManager.isDohEnabled(context);
        int poolSize = Math.min(4, configured.size());
        ExecutorService pool = Executors.newFixedThreadPool(poolSize);
        List<Future<Integer>> futures = new ArrayList<>();

        for (final WireGuardManager.TunnelConfig item : configured) {
            futures.add(pool.submit(() -> {
                try {
                    String privHex = WireGuardManager.normalizeKeyToHex(item.privateKey);
                    String pubHex = WireGuardManager.normalizeKeyToHex(item.publicKey);
                    String pskHex = WireGuardManager.safeTrim(item.presharedKey).isEmpty() ? "" : WireGuardManager.normalizeKeyToHex(item.presharedKey);
                    String ep = useDoH ? WireGuardManager.safeTrim(item.endpoint) : preResolveEndpoint(item.endpoint);
                    WgHealthAndContinuity.syncEndpointDnsHintsToNative(context, item.endpoint);
                    long rtt = Wgbridge.probeEndpointHandshakeMs(
                            privHex,
                            pskHex,
                            pubHex,
                            ep,
                            item.toEffectiveAwgParamsString(),
                            useDoH,
                            3800L
                    );
                    int ms = Math.max(1, (int) rtt);
                    WireGuardManager.sPingCacheMs.put(item.id, ms);
                    return ms;
                } catch (Throwable err) {
                    WireGuardManager.sPingCacheMs.put(item.id, -1);
                    return -1;
                }
            }));
        }

        pool.shutdown();
        pool.awaitTermination(12, TimeUnit.SECONDS);

        WireGuardManager.TunnelConfig bestCfg = null;
        int bestMs = Integer.MAX_VALUE;
        for (int i = 0; i < configured.size(); i++) {
            int ms = -1;
            try {
                ms = futures.get(i).get(100, TimeUnit.MILLISECONDS);
            } catch (Throwable ignored) {
            }
            if (ms > 0 && ms < bestMs) {
                bestMs = ms;
                bestCfg = configured.get(i);
            }
        }

        if (bestCfg == null) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.PING_ALL_FAILED);
        }

        WireGuardManager.TunnelConfig selected = WireGuardManager.selectProfile(context, bestCfg.id);
        WireGuardManager.PingWinnerResult res = new WireGuardManager.PingWinnerResult();
        res.winner = selected;
        res.bestMs = bestMs;

        boolean runningNow = WireGuardManager.isTunnelRunning(context, moduleApkPath);
        String connectedId = WireGuardManager.getConnectedProfileId(context, moduleApkPath);
        if (runningNow && !selected.id.equals(connectedId)) {
            res.livePort = WireGuardManager.startAndBindProfile(context, selected, moduleApkPath, telegramClassLoader);
            res.switchedLive = true;
        }
        return res;
    }

    /**
     * Discovers the highest unfragmented inner tunnel MTU (1420 -> 1392 -> 1360 -> 1320 -> 1280)
     * across the mobile/ISP path, saves it to the profile, and reconnects if the tunnel was active.
     */
    static int discoverAndApplyOptimalMtu(
            Context context,
            WireGuardManager.TunnelConfig draft,
            String moduleApkPath,
            ClassLoader telegramClassLoader
    ) throws Exception {
        NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
        if (!draft.hasPeerConfigured()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.MISSING_ENDPOINT);
        }

        String privHex = WireGuardManager.normalizeKeyToHex(draft.privateKey);
        String pubHex = WireGuardManager.normalizeKeyToHex(draft.publicKey);
        String pskHex = WireGuardManager.safeTrim(draft.presharedKey).isEmpty() ? "" : WireGuardManager.normalizeKeyToHex(draft.presharedKey);
        String dns = WireGuardManager.safeTrim(draft.dns).isEmpty() ? "1.1.1.1" : WireGuardManager.safeTrim(draft.dns);
        boolean useDoH = WireGuardManager.isDohEnabled(context);
        String ep = useDoH ? WireGuardManager.safeTrim(draft.endpoint) : preResolveEndpoint(draft.endpoint);

        boolean wasRunning = WireGuardManager.isTunnelRunning(context, moduleApkPath);
        if (wasRunning) {
            if (WireGuardManager.isKillSwitchEnabled(context)) {
                try {
                    int guardPort = (int) Wgbridge.startKillSwitchGuard();
                    if (guardPort > 0 && telegramClassLoader != null) {
                        WgProxyBinder.postBindTelegramProxy(context, telegramClassLoader, true, guardPort, true);
                    }
                } catch (Throwable ignored) {
                }
            }
            try {
                Wgbridge.stopTunnel();
            } catch (Throwable ignored) {
            }
        }

        try {
            WgHealthAndContinuity.syncEndpointDnsHintsToNative(context, draft.endpoint);
            long optimal = Wgbridge.discoverOptimalMTU(
                    privHex,
                    pskHex,
                    WireGuardManager.safeTrim(draft.address).isEmpty() ? "10.0.0.2/32" : WireGuardManager.safeTrim(draft.address),
                    dns,
                    pubHex,
                    ep,
                    draft.toEffectiveAwgParamsString(),
                    useDoH,
                    "",
                    2800L
            );
            int bestMtu = WireGuardManager.clampMtu((int) optimal);
            draft.mtu = bestMtu;
            WireGuardManager.saveConfig(context, draft);
            if (wasRunning) {
                WireGuardManager.startAndBindProfile(context, draft, moduleApkPath, telegramClassLoader);
            }
            return bestMtu;
        } catch (Throwable err) {
            if (wasRunning) {
                try {
                    WireGuardManager.startAndBindProfile(context, draft, moduleApkPath, telegramClassLoader);
                } catch (Throwable ignored) {
                }
            }
            throw new WgStrings.WgException(WgStrings.ErrorCode.MTU_DISCOVERY_FAILED, err.getMessage(), err);
        }
    }

    static WireGuardManager.TunnelVerifyResult verifyTunnel(Context context, String moduleApkPath) throws Exception {
        if (!WireGuardManager.isTunnelRunning(context, moduleApkPath)) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.TUNNEL_STOPPED);
        }
        boolean localRunning = false;
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            localRunning = Wgbridge.isRunning();
            if (localRunning) {
                WgHealthAndContinuity.syncHostLinkMtuSensor(context);
            }
        } catch (Throwable ignored) {
        }
        int socksPort = WireGuardManager.getActivePort(context, moduleApkPath);
        if (socksPort <= 0) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.NO_ACTIVE_PORT);
        }
        if (!localRunning && context != null) {
            WireGuardManager.sLastSharedHubCheckMs = 0L;
            WgSharedHubAndVoip.queryAnyLiveSharedTunnelPort(context);
        }
        final String socksUser = WgSyncAndCreds.getActiveSocksUser(context);
        final String socksPass = WgSyncAndCreds.getActiveSocksPass(context);

        WireGuardManager.TunnelVerifyResult res = new WireGuardManager.TunnelVerifyResult();

        Exception lastErr = null;
        byte[][] cfTargets = new byte[][]{
                new byte[]{1, 0, 0, 1},
                new byte[]{(byte) 162, (byte) 159, 36, 1},
                new byte[]{1, 1, 1, 1}
        };
        for (byte[] targetIp : cfTargets) {
            try {
                long tStart = System.nanoTime();
                try (Socket rawSocks = openSocks5Ipv4Socket(socksPort, socksUser, socksPass, targetIp, 443, 3500)) {
                    long connectDone = System.nanoTime();
                    res.tunnelPingMs = Math.max(1L, (connectDone - tStart) / 1_000_000L);

                    SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    try (SSLSocket ssl = (SSLSocket) sslFactory.createSocket(rawSocks, "one.one.one.one", 443, true)) {
                        ssl.setSoTimeout(3500);
                        ssl.startHandshake();
                        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify("one.one.one.one", ssl.getSession())) {
                            throw new SSLHandshakeException("TLS hostname mismatch");
                        }

                        OutputStream out = ssl.getOutputStream();
                        String req = "GET /cdn-cgi/trace HTTP/1.1\r\n"
                                + "Host: one.one.one.one\r\n"
                                + "User-Agent: WGPlus/1.4.0\r\n"
                                + "Connection: close\r\n\r\n";
                        out.write(req.getBytes(StandardCharsets.US_ASCII));
                        out.flush();

                        BufferedReader reader = new BufferedReader(
                                new InputStreamReader(ssl.getInputStream(), StandardCharsets.UTF_8)
                        );
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (line.startsWith("ip=")) {
                                res.exitIp = line.substring(3).trim();
                            } else if (line.startsWith("loc=")) {
                                res.countryCode = line.substring(4).trim().toUpperCase(Locale.ROOT);
                            } else if (line.startsWith("colo=")) {
                                res.colo = line.substring(5).trim();
                            }
                            if (!res.exitIp.isEmpty() && !res.countryCode.isEmpty() && !res.colo.isEmpty()) {
                                break;
                            }
                        }
                    }
                }
                if (!res.exitIp.isEmpty()) {
                    lastErr = null;
                    break;
                }
            } catch (Exception e) {
                lastErr = e;
            }
        }

        if (res.exitIp.isEmpty() && localRunning && NativeBridgeLoader.isLoaded()) {
            try {
                long retryMtu = WgHealthAndContinuity.isOuterVpnActive(context) ? 1200L : 1280L;
                Wgbridge.stepDownActiveTunnelMTU(retryMtu, "verify_retry");
                Wgbridge.ensureTunnelAlive(1800L);
                long tStart = System.nanoTime();
                try (Socket rawSocks = openSocks5Ipv4Socket(socksPort, socksUser, socksPass, cfTargets[0], 443, 3500)) {
                    res.tunnelPingMs = Math.max(1L, (System.nanoTime() - tStart) / 1_000_000L);
                    SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    try (SSLSocket ssl = (SSLSocket) sslFactory.createSocket(rawSocks, "one.one.one.one", 443, true)) {
                        ssl.setSoTimeout(3500);
                        ssl.startHandshake();
                        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify("one.one.one.one", ssl.getSession())) {
                            throw new SSLHandshakeException("TLS hostname mismatch");
                        }
                        OutputStream out = ssl.getOutputStream();
                        String req = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nUser-Agent: WGPlus/1.4.0\r\nConnection: close\r\n\r\n";
                        out.write(req.getBytes(StandardCharsets.US_ASCII));
                        out.flush();
                        BufferedReader reader = new BufferedReader(new InputStreamReader(ssl.getInputStream(), StandardCharsets.UTF_8));
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (line.startsWith("ip=")) res.exitIp = line.substring(3).trim();
                            else if (line.startsWith("loc=")) res.countryCode = line.substring(4).trim().toUpperCase(Locale.ROOT);
                            else if (line.startsWith("colo=")) res.colo = line.substring(5).trim();
                            if (!res.exitIp.isEmpty() && !res.countryCode.isEmpty() && !res.colo.isEmpty()) break;
                        }
                    }
                }
                if (!res.exitIp.isEmpty()) {
                    lastErr = null;
                }
            } catch (Exception retryEx) {
                lastErr = retryEx;
            }
        }

        if (res.exitIp.isEmpty()) {
            long tunnelAgeMs = WireGuardManager.sTunnelStartedAtMs > 0L
                    ? Math.max(0L, SystemClock.elapsedRealtime() - WireGuardManager.sTunnelStartedAtMs)
                    : 60_000L;
            if (WgHealthAndContinuity.hasActiveOsNetwork(context) && WgHealthAndContinuity.isOsNetworkValidated(context)
                    && tunnelAgeMs >= 15_000L
                    && WgSharedHubAndVoip.isHandshakeHealthyNow(context, moduleApkPath)) {
                WgTelemetryReporter.reportAnomalyAsync(
                        context,
                        moduleApkPath,
                        "VERIFY_ROUTE_FAILED",
                        lastErr != null ? lastErr.getMessage() : ""
                );
            }
            throw new WgStrings.WgException(
                    WgStrings.ErrorCode.VERIFY_ROUTE_FAILED,
                    lastErr != null ? lastErr.getMessage() : "",
                    lastErr
            );
        }

        try {
            long dcStart = System.nanoTime();
            try (Socket tgSock = openSocks5Ipv4Socket(
                    socksPort,
                    socksUser,
                    socksPass,
                    new byte[]{(byte) 149, (byte) 154, (byte) 167, 50},
                    443,
                    8000
            )) {
                res.telegramDcPingMs = Math.max(1L, (System.nanoTime() - dcStart) / 1_000_000L);
                res.telegramDcReachable = tgSock.isConnected();
            }
        } catch (Throwable ignored) {
            res.telegramDcReachable = false;
        }

        long udpLatency = probeUdpAssociateDns(socksPort, socksUser, socksPass, new byte[]{1, 1, 1, 1}, 53, 5500);
        if (udpLatency <= 0L) {
            udpLatency = probeUdpAssociateDns(socksPort, socksUser, socksPass, new byte[]{8, 8, 8, 8}, 53, 5500);
        }
        if (udpLatency > 0L) {
            res.udpCallsReady = true;
            res.udpPingMs = udpLatency;
        } else {
            res.udpCallsReady = false;
        }

        return res;
    }

    static void performSocks5ClientAuth(OutputStream out, DataInputStream in, String user, String pass) throws Exception {
        String u = user != null ? user : "";
        String p = pass != null ? pass : "";
        if (u.isEmpty() && p.isEmpty()) {
            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            byte[] greet = new byte[2];
            in.readFully(greet);
            if (greet[0] != 0x05 || greet[1] != 0x00) {
                throw new IllegalStateException("SOCKS5 auth mismatch: 0x" + Integer.toHexString(greet[1] & 0xFF));
            }
            return;
        }
        out.write(new byte[]{0x05, 0x02, 0x00, 0x02});
        out.flush();
        byte[] greet = new byte[2];
        in.readFully(greet);
        if (greet[0] != 0x05) {
            throw new IllegalStateException("SOCKS5 auth mismatch: 0x" + Integer.toHexString(greet[1] & 0xFF));
        }
        if (greet[1] == 0x00) {
            return;
        }
        if (greet[1] != 0x02) {
            throw new IllegalStateException("SOCKS5 auth mismatch: 0x" + Integer.toHexString(greet[1] & 0xFF));
        }
        byte[] uBytes = u.getBytes(StandardCharsets.UTF_8);
        byte[] pBytes = p.getBytes(StandardCharsets.UTF_8);
        if (uBytes.length > 255 || pBytes.length > 255) {
            throw new IllegalStateException("SOCKS5 credentials exceed 255 bytes");
        }
        ByteArrayOutputStream authReq = new ByteArrayOutputStream(3 + uBytes.length + pBytes.length);
        authReq.write(0x01);
        authReq.write(uBytes.length);
        authReq.write(uBytes);
        authReq.write(pBytes.length);
        authReq.write(pBytes);
        out.write(authReq.toByteArray());
        out.flush();
        byte[] authResp = new byte[2];
        in.readFully(authResp);
        if (authResp[1] != 0x00) {
            throw new IllegalStateException("SOCKS5 auth failed");
        }
    }

    private static long probeUdpAssociateDns(int localSocksPort, String user, String pass, byte[] dnsIpv4, int dnsPort, int timeoutMs) {
        try (Socket ctrlSock = new Socket()) {
            ctrlSock.connect(new InetSocketAddress("127.0.0.1", localSocksPort), 4000);
            ctrlSock.setSoTimeout(timeoutMs);

            OutputStream out = ctrlSock.getOutputStream();
            DataInputStream in = new DataInputStream(ctrlSock.getInputStream());

            performSocks5ClientAuth(out, in, user, pass);

            out.write(new byte[]{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
            out.flush();

            byte[] resp = new byte[10];
            in.readFully(resp);
            if (resp[0] != 0x05 || resp[1] != 0x00) {
                return -1L;
            }
            int relayPort = ((resp[8] & 0xFF) << 8) | (resp[9] & 0xFF);
            if (relayPort <= 0) {
                return -1L;
            }

            try (DatagramSocket udpSock = new DatagramSocket()) {
                udpSock.setSoTimeout(timeoutMs);

                byte txHi = (byte) (PROBE_RAND.nextInt(254) + 1);
                byte txLo = (byte) (PROBE_RAND.nextInt(254) + 1);

                ByteArrayOutputStream pkt = new ByteArrayOutputStream(48);
                pkt.write(new byte[]{0x00, 0x00, 0x00, 0x01});
                pkt.write(dnsIpv4);
                pkt.write((dnsPort >> 8) & 0xFF);
                pkt.write(dnsPort & 0xFF);

                pkt.write(new byte[]{
                        txHi, txLo, 0x01, 0x00,
                        0x00, 0x01, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00
                });
                pkt.write(8);
                pkt.write("telegram".getBytes(StandardCharsets.US_ASCII));
                pkt.write(3);
                pkt.write("org".getBytes(StandardCharsets.US_ASCII));
                pkt.write(0);
                pkt.write(new byte[]{0x00, 0x01, 0x00, 0x01});

                byte[] sendBytes = pkt.toByteArray();
                DatagramPacket sendPkt = new DatagramPacket(
                        sendBytes,
                        sendBytes.length,
                        InetAddress.getByName("127.0.0.1"),
                        relayPort
                );

                long startNs = System.nanoTime();
                udpSock.send(sendPkt);

                byte[] recvBuf = new byte[512];
                DatagramPacket recvPkt = new DatagramPacket(recvBuf, recvBuf.length);
                udpSock.receive(recvPkt);
                long elapsedMs = Math.max(1L, (System.nanoTime() - startNs) / 1_000_000L);

                if (recvPkt.getLength() >= 22 && recvBuf[10] == txHi && recvBuf[11] == txLo) {
                    return elapsedMs;
                }
            }
        } catch (Throwable ignored) {
        }
        return -1L;
    }

    static Socket openSocks5Ipv4Socket(int localSocksPort, String user, String pass, byte[] ipv4, int targetPort, int timeoutMs) throws Exception {
        Socket sock = new Socket();
        try {
            sock.connect(new InetSocketAddress("127.0.0.1", localSocksPort), 5000);
            sock.setSoTimeout(timeoutMs);

            OutputStream out = sock.getOutputStream();
            DataInputStream in = new DataInputStream(sock.getInputStream());

            performSocks5ClientAuth(out, in, user, pass);

            byte[] req = new byte[]{
                    0x05, 0x01, 0x00, 0x01,
                    ipv4[0], ipv4[1], ipv4[2], ipv4[3],
                    (byte) ((targetPort >> 8) & 0xFF),
                    (byte) (targetPort & 0xFF)
            };
            out.write(req);
            out.flush();

            byte[] connResp = new byte[10];
            in.readFully(connResp);
            if (connResp[1] != 0x00) {
                throw new IllegalStateException("SOCKS5 connect code " + connResp[1]);
            }
            return sock;
        } catch (Exception e) {
            try {
                sock.close();
            } catch (Throwable ignored) {
            }
            throw e;
        }
    }

    static Socket openSocks5HostSocket(int localSocksPort, String user, String pass, String targetHost, int targetPort, int timeoutMs) throws Exception {
        if (targetHost == null || targetHost.isEmpty()) {
            throw new IllegalArgumentException("Empty SOCKS5 target host");
        }
        byte[] hostBytes = targetHost.getBytes(StandardCharsets.UTF_8);
        if (hostBytes.length > 255) {
            throw new IllegalArgumentException("SOCKS5 target host too long");
        }
        Socket sock = new Socket();
        try {
            sock.connect(new InetSocketAddress("127.0.0.1", localSocksPort), 5000);
            sock.setSoTimeout(timeoutMs);

            OutputStream out = sock.getOutputStream();
            DataInputStream in = new DataInputStream(sock.getInputStream());

            performSocks5ClientAuth(out, in, user, pass);

            byte[] req = new byte[7 + hostBytes.length];
            req[0] = 0x05;
            req[1] = 0x01;
            req[2] = 0x00;
            req[3] = 0x03;
            req[4] = (byte) hostBytes.length;
            System.arraycopy(hostBytes, 0, req, 5, hostBytes.length);
            req[5 + hostBytes.length] = (byte) ((targetPort >> 8) & 0xFF);
            req[6 + hostBytes.length] = (byte) (targetPort & 0xFF);
            out.write(req);
            out.flush();

            byte[] hdr = new byte[4];
            in.readFully(hdr);
            if (hdr[1] != 0x00) {
                throw new IllegalStateException("SOCKS5 connect code " + hdr[1]);
            }
            int atyp = hdr[3] & 0xFF;
            if (atyp == 0x01) {
                in.readFully(new byte[6]);
            } else if (atyp == 0x03) {
                int domLen = in.readUnsignedByte();
                in.readFully(new byte[domLen + 2]);
            } else if (atyp == 0x04) {
                in.readFully(new byte[18]);
            } else {
                throw new IllegalStateException("SOCKS5 unsupported bind atyp " + atyp);
            }
            return sock;
        } catch (Exception e) {
            try {
                sock.close();
            } catch (Throwable ignored) {
            }
            throw e;
        }
    }
}
