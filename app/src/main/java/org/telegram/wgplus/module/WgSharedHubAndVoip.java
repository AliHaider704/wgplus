package org.telegram.wgplus.module;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import wgbridge.Wgbridge;

/**
 * Shared-tunnel hub discovery, WGP1 loopback control RPCs, owner yield/takeover,
 * and VoIP/group-call relay rewriting extracted from {@link WireGuardManager}.
 */
final class WgSharedHubAndVoip {

    private WgSharedHubAndVoip() {
    }

    static void clearReflectorIdSafe(Object ep) {
        setFieldValueSafe(ep, "reflectorId", 0);
    }

    static boolean shouldClearReflectorId(boolean isRtc, int rawPort, int localPort, boolean hasViablePrimary) {
        return !isRtc && rawPort > 0 && localPort > 0 && localPort != rawPort && hasViablePrimary;
    }

    private static Field findFieldRecursive(Class<?> cls, String fieldName) {
        Class<?> cur = cls;
        while (cur != null && cur != Object.class) {
            try {
                Field f = cur.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException ignored) {
                cur = cur.getSuperclass();
            } catch (Throwable ignored) {
                return null;
            }
        }
        return null;
    }

    static Object getFieldValueSafe(Object target, String fieldName) {
        if (target == null || fieldName == null) {
            return null;
        }
        try {
            Field f = findFieldRecursive(target.getClass(), fieldName);
            return f != null ? f.get(target) : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    static boolean getBoolFieldSafe(Object target, String fieldName, boolean fallback) {
        Object v = getFieldValueSafe(target, fieldName);
        return v instanceof Boolean ? (Boolean) v : fallback;
    }

    static int getIntFieldSafe(Object target, String fieldName, int fallback) {
        Object v = getFieldValueSafe(target, fieldName);
        return v instanceof Number ? ((Number) v).intValue() : fallback;
    }

    static long getLongFieldSafe(Object target, String fieldName, long fallback) {
        Object v = getFieldValueSafe(target, fieldName);
        return v instanceof Number ? ((Number) v).longValue() : fallback;
    }

    static String getStrFieldSafe(Object target, String fieldName, String fallback) {
        Object v = getFieldValueSafe(target, fieldName);
        return v instanceof String ? (String) v : fallback;
    }

    static boolean setFieldValueSafe(Object target, String fieldName, Object value) {
        if (target == null || fieldName == null) {
            return false;
        }
        try {
            Field f = findFieldRecursive(target.getClass(), fieldName);
            if (f == null) {
                return false;
            }
            Class<?> ft = f.getType();
            if (ft == int.class || ft == Integer.class) {
                int iv = value instanceof Number ? ((Number) value).intValue() : 0;
                if (ft == int.class) {
                    f.setInt(target, iv);
                } else {
                    f.set(target, iv);
                }
            } else if (ft == long.class || ft == Long.class) {
                long lv = value instanceof Number ? ((Number) value).longValue() : 0L;
                if (ft == long.class) {
                    f.setLong(target, lv);
                } else {
                    f.set(target, lv);
                }
            } else if (ft == boolean.class || ft == Boolean.class) {
                boolean bv = value instanceof Boolean && (Boolean) value;
                if (ft == boolean.class) {
                    f.setBoolean(target, bv);
                } else {
                    f.set(target, bv);
                }
            } else {
                f.set(target, value);
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static Object instantiateEndpointInstance(
            Class<?> compType,
            long id,
            String ipv4,
            int port,
            int tcpRelayType,
            byte[] peerTag,
            String username,
            String password
    ) {
        if (compType == null) {
            return null;
        }
        try {
            Constructor<?> ctor12 = compType.getDeclaredConstructor(
                    boolean.class, long.class, String.class, String.class,
                    int.class, int.class, byte[].class,
                    boolean.class, boolean.class, String.class, String.class, boolean.class
            );
            ctor12.setAccessible(true);
            return ctor12.newInstance(
                    false, id, ipv4, "", port, tcpRelayType, peerTag,
                    true, false, username, password, true
            );
        } catch (Throwable ignored) {
        }
        try {
            Constructor<?> noArg = compType.getDeclaredConstructor();
            noArg.setAccessible(true);
            return noArg.newInstance();
        } catch (Throwable ignored) {
        }
        try {
            Class<?> unsafeCls = Class.forName("sun.misc.Unsafe");
            Field f = unsafeCls.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            Object unsafe = f.get(null);
            return unsafeCls.getMethod("allocateInstance", Class.class).invoke(unsafe, compType);
        } catch (Throwable ignored) {
        }
        return null;
    }

    static Object cloneVoipEndpointForTcp(
            Object origEp,
            Class<?> compType,
            int tcpRelayType,
            boolean isReflectorCase
    ) {
        if (origEp == null || compType == null) {
            return null;
        }
        String ipv4 = getStrFieldSafe(origEp, "ipv4", "").trim();
        int port = getIntFieldSafe(origEp, "port", 0);
        if (!ipv4.startsWith("127.") || port <= 0 || port == 9) {
            return null;
        }
        long cloneId = getLongFieldSafe(origEp, "id", 0L) ^ 0x4000000000000000L;
        String origUser = getStrFieldSafe(origEp, "username", "");
        String origPass = getStrFieldSafe(origEp, "password", "");
        int origReflectorId = getIntFieldSafe(origEp, "reflectorId", 0);
        Object rawPeerTag = getFieldValueSafe(origEp, "peerTag");
        byte[] clonePeerTag = (isReflectorCase && rawPeerTag instanceof byte[])
                ? ((byte[]) rawPeerTag).clone()
                : null;
        String cloneUser = isReflectorCase ? "reflector" : origUser;
        int cloneReflectorId = isReflectorCase ? origReflectorId : 0;

        Object clone = instantiateEndpointInstance(
                compType, cloneId, ipv4, port, tcpRelayType, clonePeerTag, cloneUser, origPass
        );
        if (clone == null) {
            return null;
        }
        // Re-apply all fields unconditionally because Instance$Endpoint's constructor zeroes
        // username/password whenever isRtc == false and peerTag == null.
        setFieldValueSafe(clone, "isRtc", false);
        setFieldValueSafe(clone, "id", cloneId);
        setFieldValueSafe(clone, "ipv4", ipv4);
        setFieldValueSafe(clone, "ipv6", "");
        setFieldValueSafe(clone, "port", port);
        setFieldValueSafe(clone, "type", tcpRelayType);
        setFieldValueSafe(clone, "peerTag", clonePeerTag);
        setFieldValueSafe(clone, "turn", true);
        setFieldValueSafe(clone, "stun", false);
        setFieldValueSafe(clone, "tcp", true);
        setFieldValueSafe(clone, "reflectorId", cloneReflectorId);
        setFieldValueSafe(clone, "username", cloneUser);
        setFieldValueSafe(clone, "password", origPass);
        return clone;
    }

    static int resolveTcpRelayEndpointType(Class<?> instanceClass) {
        if (instanceClass != null) {
            try {
                Field f = instanceClass.getDeclaredField("ENDPOINT_TYPE_TCP_RELAY");
                f.setAccessible(true);
                return f.getInt(null);
            } catch (Throwable ignored) {
            }
        }
        return 3;
    }

    static Object[] expandEndpointsWithTcpFallbacks(
            Object[] eps,
            Class<?> endpointClass,
            Class<?> instanceClass
    ) {
        if (eps == null || eps.length == 0) {
            return eps;
        }
        Class<?> compType = eps.getClass().getComponentType();
        if (compType == null) {
            compType = endpointClass;
        }
        if (compType == null) {
            return eps;
        }
        Set<String> existingTcpKeys = new HashSet<>();
        for (Object ep : eps) {
            if (ep == null) {
                continue;
            }
            if (getBoolFieldSafe(ep, "tcp", false)) {
                String ipv4 = getStrFieldSafe(ep, "ipv4", "").trim();
                int port = getIntFieldSafe(ep, "port", 0);
                if (!ipv4.isEmpty() && port > 0) {
                    existingTcpKeys.add(ipv4 + ":" + port);
                }
            }
        }

        int tcpRelayType = resolveTcpRelayEndpointType(instanceClass);
        List<Object> clones = new ArrayList<>();
        for (Object ep : eps) {
            if (ep == null) {
                continue;
            }
            if (getBoolFieldSafe(ep, "tcp", false)) {
                continue;
            }
            String ipv4 = getStrFieldSafe(ep, "ipv4", "").trim();
            int port = getIntFieldSafe(ep, "port", 0);
            if (!ipv4.startsWith("127.") || port <= 0 || port == 9) {
                continue;
            }
            boolean isRtc = getBoolFieldSafe(ep, "isRtc", false);
            boolean turn = getBoolFieldSafe(ep, "turn", false);
            int reflectorId = getIntFieldSafe(ep, "reflectorId", 0);
            String username = getStrFieldSafe(ep, "username", "");
            boolean caseA = isRtc && turn && !username.isEmpty() && !"reflector".equals(username);
            boolean caseB = !isRtc && "reflector".equals(username) && reflectorId > 0;
            if (!caseA && !caseB) {
                continue;
            }
            String key = ipv4 + ":" + port;
            if (!existingTcpKeys.add(key)) {
                continue;
            }
            Object clone = cloneVoipEndpointForTcp(ep, compType, tcpRelayType, caseB);
            if (clone != null) {
                clones.add(clone);
            }
        }
        if (clones.isEmpty()) {
            return eps;
        }
        Object[] expanded = (Object[]) Array.newInstance(compType, eps.length + clones.size());
        System.arraycopy(eps, 0, expanded, 0, eps.length);
        for (int i = 0; i < clones.size(); i++) {
            expanded[eps.length + i] = clones.get(i);
        }
        return expanded;
    }

    static final class Wgp1StatusResult {
        final boolean running;
        final boolean hsHealthy;
        final long hsSec;
        final String profileSig;

        Wgp1StatusResult(boolean running, boolean hsHealthy, long hsSec, String profileSig) {
            this.running = running;
            this.hsHealthy = hsHealthy;
            this.hsSec = hsSec;
            this.profileSig = profileSig != null ? profileSig : "";
        }
    }

    static String patchVoipConfigJsonForProxy(String rawJson) {
        if (rawJson == null) {
            return null;
        }
        String trimmed = rawJson.trim();
        if (trimmed.isEmpty() || !trimmed.startsWith("{")) {
            return rawJson;
        }
        try {
            JSONObject obj = new JSONObject(trimmed);
            obj.put("force_tcp", true);
            obj.put("use_tcp", true);
            return obj.toString();
        } catch (Throwable ignored) {
            return rawJson
                    .replace("\"force_tcp\":false", "\"force_tcp\":true")
                    .replace("\"force_tcp\": false", "\"force_tcp\": true")
                    .replace("\"use_tcp\":false", "\"use_tcp\":true")
                    .replace("\"use_tcp\": false", "\"use_tcp\": true");
        }
    }

    /**
     * Rewrites ICE/TURN transport candidate endpoints inside tgcalls group/conference call
     * {@code setJoinResponsePayload(String)} JSON so media routes via local WireGuard relays.
     */
    static String rewriteGroupCallJoinPayload(
            String payloadJson,
            WireGuardManager.EndpointRelayStarter relayStarter,
            boolean killSwitchBlackhole
    ) {
        if (relayStarter == null) {
            return payloadJson;
        }
        return rewriteGroupCallJoinPayloadAddr(
                payloadJson,
                (host, port) -> {
                    int lp = relayStarter.startRelay(host, port);
                    return lp > 0 ? ("127.0.0.1:" + lp) : "";
                },
                killSwitchBlackhole
        );
    }

    static String rewriteGroupCallJoinPayloadAddr(
            String payloadJson,
            WireGuardManager.EndpointAddrRelayStarter relayStarter,
            boolean killSwitchBlackhole
    ) {
        if (payloadJson == null || payloadJson.isEmpty() || relayStarter == null) {
            return payloadJson;
        }
        String trimmed = payloadJson.trim();
        if (!trimmed.startsWith("{")) {
            return payloadJson;
        }
        try {
            JSONObject root = new JSONObject(trimmed);
            JSONObject transport = root.optJSONObject("transport");
            JSONArray candidates = transport != null ? transport.optJSONArray("candidates") : null;
            if (candidates == null) {
                candidates = root.optJSONArray("candidates");
            }
            if (candidates == null || candidates.length() == 0) {
                return payloadJson;
            }
            boolean changed = false;
            for (int i = 0; i < candidates.length(); i++) {
                JSONObject cand = candidates.optJSONObject(i);
                if (cand == null) {
                    continue;
                }
                String ipField = cand.has("ip") ? "ip" : (cand.has("address") ? "address" : "ip");
                String host = cand.optString(ipField, "").trim();
                Object portObj = cand.opt("port");
                int rawPort = -1;
                if (portObj instanceof Number) {
                    rawPort = ((Number) portObj).intValue();
                } else if (portObj instanceof String) {
                    try {
                        rawPort = Integer.parseInt(((String) portObj).trim());
                    } catch (NumberFormatException ignored) {
                    }
                }
                if (host.isEmpty() || rawPort < 1 || rawPort > 65535) {
                    continue;
                }
                if (host.startsWith("127.") || "::1".equals(host)) {
                    continue;
                }

                String relayAddr = relayStarter.startRelayAddr(host, rawPort);
                String relayIp = parseIpFromHostPort(relayAddr);
                int localPort = parsePortFromHostPort(relayAddr);
                if (localPort <= 0 && killSwitchBlackhole) {
                    relayIp = "127.0.0.1";
                    localPort = 9;
                }
                if (!relayIp.isEmpty() && localPort > 0) {
                    cand.put(ipField, relayIp);
                    if (portObj instanceof Number) {
                        cand.put("port", localPort);
                    } else {
                        cand.put("port", String.valueOf(localPort));
                    }
                    changed = true;
                }
            }
            return changed ? root.toString() : payloadJson;
        } catch (Throwable ignored) {
            return payloadJson;
        }
    }

    static boolean isUsingSharedHub() {
        WireGuardManager.SharedHubSnapshot hub = WireGuardManager.sSharedHub;
        if (hub.isOwner || hub.port <= 0) {
            return false;
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return true;
        }
        return isLocalLoopbackPortOpen(hub.port, 120);
    }

    static int queryAnyLiveSharedTunnelPort(Context context) {
        WireGuardManager.SharedHubSnapshot hub = WireGuardManager.sSharedHub;
        if (context == null) {
            return isUsingSharedHub() ? hub.port : -1;
        }
        if (hub.isOwner) {
            return -1;
        }
        long now = SystemClock.elapsedRealtime();
        boolean onMain = (Looper.myLooper() == Looper.getMainLooper());
        if (now - WireGuardManager.sLastSharedHubCheckMs < 2000L && WireGuardManager.sCachedExternalSharedPort > 0) {
            if (onMain || isLocalLoopbackPortOpen(WireGuardManager.sCachedExternalSharedPort, 120)) {
                return WireGuardManager.sCachedExternalSharedPort;
            }
        }
        try {
            int port = -1;
            String owner = "";
            String sharedUser = "";
            String sharedPass = "";
            long updatedAt = 0L;
            long lastHsSec = 0L;
            boolean hsHealthy = false;
            String myPkg = context.getPackageName();
            if ("org.telegram.wgplus.module".equals(myPkg)) {
                SharedPreferences sp = context.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
                port = sp.getInt("port", -1);
                owner = sp.getString("owner", "");
                sharedUser = sp.getString("socksUser", "");
                sharedPass = sp.getString("socksPass", "");
                updatedAt = sp.getLong("updatedAt", 0L);
                lastHsSec = sp.getLong("lastHsSec", 0L);
                hsHealthy = sp.getBoolean("hsHealthy", false);
            } else {
                Bundle out = context.getContentResolver().call(
                        Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                        KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                        null,
                        null
                );
                if (out != null) {
                    port = out.getInt("port", -1);
                    owner = out.getString("owner", "");
                    sharedUser = out.getString("socksUser", "");
                    sharedPass = out.getString("socksPass", "");
                    updatedAt = out.getLong("updatedAt", 0L);
                    lastHsSec = out.getLong("lastHsSec", 0L);
                    hsHealthy = out.getBoolean("hsHealthy", false);
                }
            }
            if (port > 0 && (myPkg == null || !myPkg.equals(owner))) {
                boolean recent = updatedAt <= 0L || Math.abs(System.currentTimeMillis() - updatedAt) < 300_000L;
                Wgp1StatusResult liveRes = queryLiveStatusWithFallback(context, null, port, sharedPass, null);
                if (liveRes != null && liveRes.running) {
                    long nextHs = liveRes.hsSec > 0L ? liveRes.hsSec : (liveRes.hsHealthy ? lastHsSec : 0L);
                    WireGuardManager.updateSharedHubClient(port, sharedUser, sharedPass, nextHs, liveRes.hsHealthy);
                    WireGuardManager.sCachedExternalSharedPort = port;
                    WireGuardManager.sLastSharedHubCheckMs = now;
                    return port;
                }
                if (!onMain && !NativeBridgeLoader.isLoaded() && isLocalLoopbackPortOpen(port, 160)) {
                    WireGuardManager.updateSharedHubClient(port, sharedUser, sharedPass, lastHsSec, hsHealthy);
                    WireGuardManager.sCachedExternalSharedPort = port;
                    WireGuardManager.sLastSharedHubCheckMs = now;
                    return port;
                }
                if (onMain && recent && !WireGuardManager.sSharedHubProbeInFlight) {
                    final int probePort = port;
                    final String candUser = sharedUser != null ? sharedUser : "";
                    final String candPass = sharedPass != null ? sharedPass : "";
                    final long candHsSec = lastHsSec;
                    final boolean candHsHealthy = hsHealthy;
                    WireGuardManager.sSharedHubProbeInFlight = true;
                    WireGuardManager.SYNC_EXEC.execute(() -> {
                        try {
                            Wgp1StatusResult bgRes = queryLiveStatusWithFallback(context, null, probePort, candPass, null);
                            WireGuardManager.sLastSharedHubCheckMs = SystemClock.elapsedRealtime();
                            if (bgRes != null && bgRes.running) {
                                WireGuardManager.updateSharedHubClient(
                                        probePort,
                                        candUser,
                                        candPass,
                                        bgRes.hsSec > 0L ? bgRes.hsSec : candHsSec,
                                        bgRes.hsHealthy || candHsHealthy
                                );
                                WireGuardManager.sCachedExternalSharedPort = probePort;
                            } else {
                                WireGuardManager.sCachedExternalSharedPort = -1;
                            }
                        } finally {
                            WireGuardManager.sSharedHubProbeInFlight = false;
                        }
                    });
                }
            }
        } catch (Throwable ignored) {
        }
        // Fallback when package-visibility restrictions block ContentResolver IPC:
        // probe localhost WGP1 mux ports directly via Go (safe on Main Thread too once libgojni is loaded).
        int wgpPort = probeSharedTunnelOverWgp1(context, null);
        if (wgpPort > 0) {
            return wgpPort;
        }
        WireGuardManager.sLastSharedHubCheckMs = now;
        WireGuardManager.sCachedExternalSharedPort = -1;
        return -1;
    }

    static boolean isSharedTunnelObserved(Context context, String moduleApkPath) {
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            if (Wgbridge.isRunning()) {
                return false;
            }
        } catch (Throwable ignored) {
        }
        return queryAnyLiveSharedTunnelPort(context) > 0;
    }

    static boolean isLocalLoopbackPortOpen(int port, int timeoutMs) {
        if (port <= 0 || port > 65535) return false;
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return false;
        }
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", port), timeoutMs);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    static String parseIpFromHostPort(String hostPort) {
        if (hostPort == null) {
            return "";
        }
        String s = hostPort.trim();
        int idx = s.lastIndexOf(':');
        if (idx <= 0 || idx >= s.length() - 1) {
            return "";
        }
        return s.substring(0, idx).trim();
    }

    static int parsePortFromHostPort(String hostPort) {
        if (hostPort == null) {
            return 0;
        }
        String s = hostPort.trim();
        int idx = s.lastIndexOf(':');
        if (idx < 0 || idx >= s.length() - 1) {
            return 0;
        }
        try {
            int p = Integer.parseInt(s.substring(idx + 1).trim());
            return (p > 0 && p <= 65535) ? p : 0;
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    /** Starts a local VoIP relay socket inside this process if its own Go tunnel is active. */
    static int startLocalVoipEndpointRelay(Context ctx, String targetHost, int targetPort) {
        return parsePortFromHostPort(startLocalVoipEndpointRelayAddr(ctx, targetHost, targetPort));
    }

    static String startLocalVoipEndpointRelayAddr(Context ctx, String targetHost, int targetPort) {
        String host = targetHost != null ? targetHost.trim() : "";
        if (host.isEmpty() || targetPort < 1 || targetPort > 65535) {
            return "";
        }
        try {
            NativeBridgeLoader.ensureLoaded(ctx, null);
            if (!Wgbridge.isRunning()) {
                return "";
            }
            String addr = Wgbridge.startVoipEndpointRelayAddr(host, targetPort);
            return addr != null ? addr.trim() : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Sends a single-line WGP1 control command over loopback via Go JNI (immune to NetworkOnMainThreadException). */
    private static String sendWgp1ControlCommand(int muxPort, String socksPass, String command) {
        if (muxPort < 1 || muxPort > 65535 || command == null || command.isEmpty()) {
            return "";
        }
        String passTok = (socksPass != null && !socksPass.trim().isEmpty()) ? socksPass.trim() : "-";
        try {
            if (NativeBridgeLoader.isLoaded()) {
                String resp = Wgbridge.sendLocalWgp1Command(muxPort, passTok, command, 350L);
                if (resp != null) {
                    return resp.trim();
                }
            }
        } catch (Throwable ignored) {
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return "";
        }
        String line = "WGP1 " + passTok + " " + command + "\n";
        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress("127.0.0.1", muxPort), 350);
            sock.setSoTimeout(450);
            OutputStream os = sock.getOutputStream();
            os.write(line.getBytes(StandardCharsets.UTF_8));
            os.flush();
            BufferedReader br = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
            String resp = br.readLine();
            return resp != null ? resp.trim() : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Opens or reuses a local VoIP relay socket directly inside whichever local process owns {@code muxPort}. */
    static int requestVoipRelayOverWgp1(int muxPort, String socksPass, String targetHost, int targetPort) {
        return parsePortFromHostPort(requestVoipRelayOverWgp1Addr(muxPort, socksPass, targetHost, targetPort));
    }

    static String requestVoipRelayOverWgp1Addr(int muxPort, String socksPass, String targetHost, int targetPort) {
        if (muxPort < 1 || muxPort > 65535 || targetHost == null || targetHost.trim().isEmpty()
                || targetPort < 1 || targetPort > 65535) {
            return "";
        }
        String host = targetHost.trim();
        try {
            if (NativeBridgeLoader.isLoaded()) {
                String passTok = (socksPass != null && !socksPass.trim().isEmpty()) ? socksPass.trim() : "-";
                String goAddr = Wgbridge.requestRemoteVoipRelayAddr(muxPort, passTok, host, targetPort);
                if (goAddr != null && !goAddr.trim().isEmpty()) {
                    return goAddr.trim();
                }
            }
        } catch (Throwable ignored) {
        }
        String resp = sendWgp1ControlCommand(muxPort, socksPass, "VOIP_RELAY_ADDR " + host + " " + targetPort);
        if (resp.startsWith("OK ")) {
            String addr = resp.substring(3).trim();
            if (parsePortFromHostPort(addr) > 0 && !parseIpFromHostPort(addr).isEmpty()) {
                return addr;
            }
        }
        String respLegacy = sendWgp1ControlCommand(muxPort, socksPass, "VOIP_RELAY " + host + " " + targetPort);
        if (respLegacy.startsWith("OK ")) {
            try {
                int port = Integer.parseInt(respLegacy.substring(3).trim());
                if (port > 0 && port <= 65535) {
                    return "127.0.0.1:" + port;
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return "";
    }

    static String startRemoteVoipRelayOverWgp1Addr(Context ctx, String targetHost, int targetPort) {
        String host = targetHost != null ? targetHost.trim() : "";
        if (host.isEmpty() || targetPort < 1 || targetPort > 65535) {
            return "";
        }
        try {
            NativeBridgeLoader.ensureLoaded(ctx, null);
        } catch (Throwable ignored) {
        }
        int regPort = -1;
        String regPass = "";
        if (ctx != null && "org.telegram.wgplus.module".equals(ctx.getPackageName())) {
            try {
                SharedPreferences sp = ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
                regPort = sp.getInt("port", -1);
                regPass = sp.getString("socksPass", "");
            } catch (Throwable ignored) {
            }
        }
        String activePass = ctx != null ? WgSyncAndCreds.getActiveSocksPass(ctx) : WireGuardManager.sSocksCreds.pass;
        int[] ports = new int[]{regPort, 48729, 48730, 48731, 48732};
        for (int p : ports) {
            if (p <= 0) {
                continue;
            }
            if (regPass != null && !regPass.isEmpty()) {
                String a = requestVoipRelayOverWgp1Addr(p, regPass, host, targetPort);
                if (!a.isEmpty()) {
                    return a;
                }
            }
            if (activePass != null && !activePass.isEmpty() && !activePass.equals(regPass)) {
                String a = requestVoipRelayOverWgp1Addr(p, activePass, host, targetPort);
                if (!a.isEmpty()) {
                    return a;
                }
            }
        }
        return "";
    }

    /** Queries full status including optional 5th profileSig field from whichever process owns {@code muxPort}. */
    static Wgp1StatusResult queryLiveStatusFullOverWgp1(int muxPort, String socksPass) {
        return parseWgp1StatusLine(sendWgp1ControlCommand(muxPort, socksPass, "STATUS"), false);
    }

    static Wgp1StatusResult queryPublicStatusOverWgp1(int muxPort) {
        return parseWgp1StatusLine(sendWgp1ControlCommand(muxPort, "-", "PUBLIC_STATUS"), true);
    }

    private static Wgp1StatusResult parseWgp1StatusLine(String resp, boolean isPublicHash) {
        if (resp == null || !resp.startsWith("OK ")) {
            return null;
        }
        String[] parts = resp.substring(3).trim().split("\\s+", 4);
        if (parts.length < 3) {
            return null;
        }
        try {
            boolean up = "true".equals(parts[0]);
            boolean hs = "true".equals(parts[1]);
            long hsSec = Long.parseLong(parts[2]);
            String rawSig = parts.length >= 4 ? parts[3].trim() : "";
            String sig = isPublicHash
                    ? ((!rawSig.isEmpty() && !"-".equals(rawSig)) ? ("HASH:" + rawSig) : "")
                    : rawSig;
            return new Wgp1StatusResult(up, hs, hsSec, sig);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    static Wgp1StatusResult queryLiveStatusWithFallback(
            Context ctx,
            String moduleApkPath,
            int muxPort,
            String socksPass,
            String requiredSig
    ) {
        if (muxPort < 1 || muxPort > 65535) {
            return null;
        }
        if (ctx != null && !NativeBridgeLoader.isLoaded()) {
            try {
                NativeBridgeLoader.ensureLoaded(ctx, moduleApkPath);
            } catch (Throwable ignored) {
            }
        }
        if (socksPass != null && !socksPass.isEmpty()) {
            Wgp1StatusResult full = queryLiveStatusFullOverWgp1(muxPort, socksPass);
            if (full != null) {
                return full;
            }
        }
        Wgp1StatusResult pub = queryPublicStatusOverWgp1(muxPort);
        if (pub != null && wgp1ProfileSigMatches(ctx, requiredSig, pub.profileSig)) {
            return pub;
        }
        return null;
    }

    /** Queries live {running(0|1), handshakeHealthy(0|1), lastHandshakeSec} from whichever process owns {@code muxPort}. */
    static long[] queryLiveStatusOverWgp1(int muxPort, String socksPass) {
        Wgp1StatusResult res = queryLiveStatusFullOverWgp1(muxPort, socksPass);
        if (res == null) {
            return null;
        }
        return new long[]{res.running ? 1L : 0L, res.hsHealthy ? 1L : 0L, res.hsSec};
    }

    static boolean wgp1ProfileSigMatches(Context context, String requiredSig, String peerSig) {
        if (requiredSig == null || requiredSig.isEmpty()) {
            return true;
        }
        if (peerSig == null || peerSig.isEmpty()) {
            return false;
        }
        if (peerSig.startsWith("HASH:")) {
            String peerHash = peerSig.substring(5).trim();
            if (peerHash.isEmpty()) {
                return false;
            }
            if (peerHash.equalsIgnoreCase(WgSyncAndCreds.computeProfileSigHash(requiredSig))) {
                return true;
            }
            if (context != null && !WireGuardManager.isDohEnabled(context)) {
                int reqBar = requiredSig.lastIndexOf('|');
                if (reqBar > 0) {
                    try {
                        String pre = WgTunnelProber.preResolveEndpoint(requiredSig.substring(0, reqBar).trim());
                        if (pre != null && !pre.isEmpty()) {
                            String altSig = pre + "|" + requiredSig.substring(reqBar + 1).trim();
                            if (peerHash.equalsIgnoreCase(WgSyncAndCreds.computeProfileSigHash(altSig))) {
                                return true;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
            return false;
        }
        if (requiredSig.equals(peerSig)) {
            return true;
        }
        // When DoH is disabled, StartTunnelAdvanced receives preResolved IP instead of hostname;
        // also accept an exact peer public key match when endpoints resolve identically.
        int reqBar = requiredSig.lastIndexOf('|');
        int peerBar = peerSig.lastIndexOf('|');
        if (reqBar > 0 && peerBar > 0) {
            String reqEp = requiredSig.substring(0, reqBar).trim();
            String reqPub = requiredSig.substring(reqBar + 1).trim();
            String peerEp = peerSig.substring(0, peerBar).trim();
            String peerPub = peerSig.substring(peerBar + 1).trim();
            if (!reqPub.isEmpty() && reqPub.equals(peerPub)) {
                if (reqEp.equalsIgnoreCase(peerEp)) {
                    return true;
                }
                if (context != null && !WireGuardManager.isDohEnabled(context)) {
                    try {
                        String pre = WgTunnelProber.preResolveEndpoint(reqEp);
                        if (pre != null && pre.equalsIgnoreCase(peerEp)) {
                            return true;
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
        return false;
    }

    /**
     * Loopback WGP1 shared-hub discovery fallback for hosts without QUERY_ALL_PACKAGES
     * (e.g. official Telegram 13.3.1 on targetSdk 34+), preventing duplicate concurrent tunnels.
     */
    private static int probeSharedTunnelOverWgp1(Context context, String requiredProfileSig) {
        if (context == null) {
            return -1;
        }
        try {
            NativeBridgeLoader.ensureLoaded(context, null);
        } catch (Throwable ignored) {
        }
        if (Looper.myLooper() == Looper.getMainLooper() && !NativeBridgeLoader.isLoaded()) {
            return -1;
        }
        WgSyncAndCreds.ensureSessionSocksCredentials(context);
        WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
        String user = creds.user;
        String pass = creds.pass;
        if (pass.isEmpty()) {
            try {
                SharedPreferences sp = WireGuardManager.getPrefs(context);
                user = sp.getString(WireGuardManager.KEY_PERSISTED_SOCKS_USER, user);
                pass = sp.getString(WireGuardManager.KEY_PERSISTED_SOCKS_PASS, "");
            } catch (Throwable ignored) {
            }
        }

        int myPort = -1;
        try {
            if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                myPort = (int) Wgbridge.getActivePort();
            }
        } catch (Throwable ignored) {
        }

        int[] candidatePorts = new int[]{48729, 48730, 48731, 48732};
        for (int p : candidatePorts) {
            if (p == myPort) {
                continue;
            }
            Wgp1StatusResult res = queryLiveStatusWithFallback(context, null, p, pass, requiredProfileSig);
            if (res != null && res.running && wgp1ProfileSigMatches(context, requiredProfileSig, res.profileSig)) {
                WireGuardManager.SharedHubSnapshot prev = WireGuardManager.sSharedHub;
                String effUser = (user != null && !user.isEmpty() && pass != null && !pass.isEmpty()) ? user : prev.user;
                String effPass = (user != null && !user.isEmpty() && pass != null && !pass.isEmpty()) ? pass : prev.pass;
                WireGuardManager.updateSharedHubClient(p, effUser, effPass, res.hsSec, res.hsHealthy);
                WireGuardManager.sCachedExternalSharedPort = p;
                WireGuardManager.sLastSharedHubCheckMs = SystemClock.elapsedRealtime();
                return p;
            }
        }
        return -1;
    }

    /**
     * Binds or reuses a local loopback UDP/TCP relay for a Telegram VoIP relay server,
     * preserving {@code targetPort} on {@code 127.0.0.x} when {@code targetPort >= 1024} so WebRTC
     * {@code ReflectorPort} and {@code TurnPort} accept remote candidates seamlessly, and executing
     * all WGP1 RPCs via Go JNI so Android's Main UI Thread never throws NetworkOnMainThreadException.
     */
    /**
     * Legacy 127.0.0.1-only port helper. Prefer {@link #startVoipEndpointRelayAddr} so callers
     * receive the exact bound loopback IP ({@code 127.0.0.1} or {@code 127.0.0.x}) and port.
     */
    static int startVoipEndpointRelay(Context ctx, String moduleApkPath, String targetHost, int targetPort) {
        String host = targetHost != null ? targetHost.trim() : "";
        if (host.isEmpty() || targetPort < 1 || targetPort > 65535) {
            return 0;
        }
        try {
            NativeBridgeLoader.ensureLoaded(ctx, moduleApkPath);
            if (Wgbridge.isRunning()) {
                return (int) Wgbridge.startVoipEndpointRelay(host, targetPort);
            }
        } catch (Throwable ignored) {
        }
        String addr = startVoipEndpointRelayAddr(ctx, moduleApkPath, host, targetPort);
        return "127.0.0.1".equals(parseIpFromHostPort(addr)) ? parsePortFromHostPort(addr) : 0;
    }

    static String startVoipEndpointRelayAddr(Context ctx, String moduleApkPath, String targetHost, int targetPort) {
        String host = targetHost != null ? targetHost.trim() : "";
        if (host.isEmpty() || targetPort < 1 || targetPort > 65535) {
            return "";
        }
        try {
            NativeBridgeLoader.ensureLoaded(ctx, moduleApkPath);
            if (Wgbridge.isRunning()) {
                String localAddr = Wgbridge.startVoipEndpointRelayAddr(host, targetPort);
                if (localAddr != null && !localAddr.trim().isEmpty()) {
                    return localAddr.trim();
                }
            }
        } catch (Throwable ignored) {
        }
        try {
            int activeMuxPort = WireGuardManager.getActivePort(ctx, moduleApkPath);
            String pass = WgSyncAndCreds.getActiveSocksPass(ctx);
            String sharedPass = WireGuardManager.sSharedHub.pass;
            String detPass = "";
            if (ctx != null) {
                try {
                    WireGuardManager.TunnelConfig cfg = WireGuardManager.loadConfig(ctx);
                    if (cfg != null && !WireGuardManager.safeTrim(cfg.privateKey).isEmpty()) {
                        detPass = WgSyncAndCreds.deriveProfileSocksPass(cfg.privateKey);
                    }
                } catch (Throwable ignored) {
                }
            }
            int[] candidatePorts = new int[]{activeMuxPort, 48729, 48730, 48731, 48732};
            for (int p : candidatePorts) {
                if (p <= 0) {
                    continue;
                }
                if (pass != null && !pass.isEmpty()) {
                    String addr = requestVoipRelayOverWgp1Addr(p, pass, host, targetPort);
                    if (!addr.isEmpty()) {
                        return addr;
                    }
                }
                if (sharedPass != null && !sharedPass.isEmpty() && !sharedPass.equals(pass)) {
                    String addr = requestVoipRelayOverWgp1Addr(p, sharedPass, host, targetPort);
                    if (!addr.isEmpty()) {
                        return addr;
                    }
                }
                if (!detPass.isEmpty() && !detPass.equals(pass) && !detPass.equals(sharedPass)) {
                    String addr = requestVoipRelayOverWgp1Addr(p, detPass, host, targetPort);
                    if (!addr.isEmpty()) {
                        return addr;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        if (ctx != null && !"org.telegram.wgplus.module".equals(ctx.getPackageName())) {
            try {
                Bundle req = new Bundle();
                req.putString(KeepaliveStatusProvider.EXTRA_HOST, host);
                req.putInt(KeepaliveStatusProvider.EXTRA_PORT, targetPort);
                Bundle out = ctx.getContentResolver().call(
                        WireGuardManager.STATUS_PROVIDER_URI,
                        KeepaliveStatusProvider.METHOD_START_VOIP_RELAY,
                        null,
                        req
                );
                if (out != null) {
                    String addr = out.getString(KeepaliveStatusProvider.RESULT_LOCAL_ADDR, "");
                    if (addr != null && !addr.trim().isEmpty()) {
                        return addr.trim();
                    }
                    int lp = out.getInt(KeepaliveStatusProvider.RESULT_LOCAL_PORT, 0);
                    if (lp > 0) {
                        return "127.0.0.1:" + lp;
                    }
                }
            } catch (Throwable t) {
                Log.w(WireGuardManager.TAG, "startVoipEndpointRelayAddr IPC warning: " + t.getMessage());
            }
            if (Looper.myLooper() != Looper.getMainLooper()) {
                try {
                    if (ensureSharedHubResponsiveOrTakeOver(ctx, moduleApkPath, ctx.getClassLoader(), "voip_relay_unresponsive")
                            && Wgbridge.isRunning()) {
                        String localAddr = Wgbridge.startVoipEndpointRelayAddr(host, targetPort);
                        if (localAddr != null && !localAddr.trim().isEmpty()) {
                            return localAddr.trim();
                        }
                    }
                } catch (Throwable ignored) {
                }
            }
        }
        return "";
    }

    static boolean shouldTakeOverSharedTunnelFromUnprotectedOwner(
            String myPkg,
            String ownerPkg,
            boolean daemonOrRootActive
    ) {
        return myPkg != null
                && !myPkg.trim().isEmpty()
                && !"org.telegram.wgplus.module".equals(myPkg.trim())
                && "org.telegram.wgplus.module".equals(ownerPkg != null ? ownerPkg.trim() : "")
                && !daemonOrRootActive;
    }

    static boolean yieldLocalTunnelForForegroundClient(Context context) {
        synchronized (WireGuardManager.class) {
            boolean wasActive = false;
            WgHealthAndContinuity.stopFailoverMonitor();
            if (context != null) {
                WgHealthAndContinuity.unregisterNetworkWatchdog(context);
            }
            WgHealthAndContinuity.releaseForcedContinuityLocks();
            WireGuardManager.clearSharedHubState();
            WireGuardManager.sCachedExternalSharedPort = -1;
            try {
                if (NativeBridgeLoader.isLoaded()) {
                    wasActive = Wgbridge.isRunning() || Wgbridge.getKillSwitchPort() > 0L;
                    Wgbridge.setKillSwitchArmed(false);
                    Wgbridge.stopKillSwitchGuard();
                    Wgbridge.stopTunnel();
                }
            } catch (Throwable ignored) {
            }
            if (wasActive) {
                WgDiagnosticsLog.record("TUNNEL", "YIELD_LOCAL", "released local mux for foreground client");
            }
            return wasActive;
        }
    }

    private static void requestSharedOwnerYield(Context context, int sharedPort, String sharedPass) {
        if (context != null && Looper.myLooper() != Looper.getMainLooper()) {
            try {
                context.getContentResolver().call(
                        WireGuardManager.STATUS_PROVIDER_URI,
                        KeepaliveStatusProvider.METHOD_REQUEST_YIELD_TUNNEL,
                        context.getPackageName(),
                        null
                );
            } catch (Throwable ignored) {
            }
        }
        try {
            if (NativeBridgeLoader.isLoaded() && sharedPort > 0) {
                String effPass = (sharedPass != null && !sharedPass.isEmpty()) ? sharedPass : WgSyncAndCreds.getActiveSocksPass(context);
                if (!Wgbridge.requestRemoteTunnelYield(sharedPort, effPass != null ? effPass : "")) {
                    String detPass = "";
                    if (context != null) {
                        WireGuardManager.TunnelConfig cfg = WireGuardManager.loadConfig(context);
                        if (cfg != null && !WireGuardManager.safeTrim(cfg.privateKey).isEmpty()) {
                            detPass = WgSyncAndCreds.deriveProfileSocksPass(cfg.privateKey);
                        }
                    }
                    if (!detPass.isEmpty() && !detPass.equals(effPass)) {
                        Wgbridge.requestRemoteTunnelYield(sharedPort, detPass);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    static boolean ensureSharedHubResponsiveOrTakeOver(
            Context appCtx,
            String moduleApkPath,
            ClassLoader telegramClassLoader,
            String reason
    ) {
        if (appCtx == null || Looper.myLooper() == Looper.getMainLooper()) {
            return false;
        }
        String myPkg = appCtx.getPackageName();
        if ("org.telegram.wgplus.module".equals(myPkg)) {
            return false;
        }
        try {
            NativeBridgeLoader.ensureLoaded(appCtx, moduleApkPath);
            if (Wgbridge.isRunning()) {
                return false;
            }
        } catch (Throwable ignored) {
            return false;
        }
        long now = SystemClock.elapsedRealtime();
        if (now - WireGuardManager.sLastAutoTakeoverAttemptMs < 4000L) {
            return false;
        }
        WireGuardManager.SharedHubSnapshot hub = WireGuardManager.sSharedHub;
        int port = hub.port > 0 ? hub.port : queryAnyLiveSharedTunnelPort(appCtx);
        if (port <= 0) {
            return false;
        }
        String owner = "";
        String sharedPass = WireGuardManager.sSharedHub.pass;
        boolean daemonOrRootActive = false;
        long updatedAt = 0L;
        try {
            Bundle out = appCtx.getContentResolver().call(
                    WireGuardManager.STATUS_PROVIDER_URI,
                    KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                    null,
                    null
            );
            if (out != null) {
                owner = out.getString("owner", "");
                String sp = out.getString("socksPass", "");
                if (sp != null && !sp.isEmpty()) {
                    sharedPass = sp;
                }
                daemonOrRootActive = out.getBoolean("daemonOrRootActive", false);
                updatedAt = out.getLong("updatedAt", 0L);
            }
        } catch (Throwable ignored) {
        }
        boolean unprotectedCompanion = shouldTakeOverSharedTunnelFromUnprotectedOwner(myPkg, owner, daemonOrRootActive);
        Wgp1StatusResult live = queryLiveStatusWithFallback(appCtx, moduleApkPath, port, sharedPass, null);
        boolean ownerUnresponsive = (live == null || !live.running);
        if (!unprotectedCompanion && ownerUnresponsive) {
            try {
                Thread.sleep(450L);
            } catch (InterruptedException ignored) {
            }
            String retryResp = "";
            try {
                if (NativeBridgeLoader.isLoaded()) {
                    String passTok = (sharedPass != null && !sharedPass.trim().isEmpty()) ? sharedPass.trim() : "-";
                    retryResp = Wgbridge.sendLocalWgp1Command(port, passTok, "STATUS", 900L);
                }
            } catch (Throwable ignored) {
            }
            Wgp1StatusResult retry = parseWgp1StatusLine(retryResp, false);
            if (retry == null) {
                retry = queryLiveStatusWithFallback(appCtx, moduleApkPath, port, sharedPass, null);
            }
            if ((retry != null && retry.running)
                    || (updatedAt > 0L && Math.abs(System.currentTimeMillis() - updatedAt) < 12_000L
                        && (!unprotectedCompanion || isLocalLoopbackPortOpen(port, 400)))) {
                return false;
            }
        }
        if (!unprotectedCompanion && !ownerUnresponsive) {
            return false;
        }

        WireGuardManager.sLastAutoTakeoverAttemptMs = now;
        requestSharedOwnerYield(appCtx, port, sharedPass);
        WireGuardManager.clearSharedHubState();
        WireGuardManager.sCachedExternalSharedPort = -1;
        WireGuardManager.sLastSharedHubCheckMs = 0L;
        String diagDetail = "port=" + port + " owner=" + (owner.isEmpty() ? "?" : owner)
                + " unprotected=" + unprotectedCompanion + " reason=" + reason;
        WgDiagnosticsLog.record("TUNNEL", "FROZEN_OWNER_TAKEOVER", diagDetail);
        WgTelemetryReporter.reportAnomalyAsync(appCtx, moduleApkPath, "FROZEN_OWNER_TAKEOVER", diagDetail);

        WireGuardManager.TunnelConfig cfg = WireGuardManager.getConnectedProfile(appCtx, moduleApkPath);
        if (cfg == null || !cfg.hasPeerConfigured()) {
            cfg = WireGuardManager.loadConfig(appCtx);
        }
        if (cfg == null || !cfg.hasPeerConfigured()) {
            return false;
        }
        try {
            int newPort = WireGuardManager.startAndBindProfile(appCtx, cfg, moduleApkPath, telegramClassLoader);
            return newPort > 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    static int queryLiveSharedTunnelPort(Context context, String profileSig) {
        if (context == null || profileSig == null || profileSig.isEmpty()) return -1;
        try {
            NativeBridgeLoader.ensureLoaded(context, null);
        } catch (Throwable ignored) {
        }
        try {
            Bundle out = context.getContentResolver().call(
                    Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                    KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                    null,
                    null
            );
            if (out != null) {
                int port = out.getInt("port", -1);
                String sig = out.getString("sig", "");
                String owner = out.getString("owner", "");
                String sharedUser = out.getString("socksUser", "");
                String sharedPass = out.getString("socksPass", "");
                boolean daemonOrRootActive = out.getBoolean("daemonOrRootActive", false);
                String myPkg = context.getPackageName();
                if (port > 0 && wgp1ProfileSigMatches(context, profileSig, sig) && myPkg != null && !myPkg.equals(owner)) {
                    if (Looper.myLooper() != Looper.getMainLooper()
                            && shouldTakeOverSharedTunnelFromUnprotectedOwner(myPkg, owner, daemonOrRootActive)) {
                        requestSharedOwnerYield(context, port, sharedPass);
                        return -1;
                    }
                    Wgp1StatusResult live = queryLiveStatusWithFallback(context, null, port, sharedPass, profileSig);
                    if ((live != null && live.running) || (!NativeBridgeLoader.isLoaded() && isLocalLoopbackPortOpen(port, 250))) {
                        long hsSec = live != null && live.hsSec > 0L ? live.hsSec : out.getLong("lastHsSec", 0L);
                        boolean hsHealthy = (live != null && live.hsHealthy) || out.getBoolean("hsHealthy", false);
                        WireGuardManager.updateSharedHubClient(port, sharedUser, sharedPass, hsSec, hsHealthy);
                        WgSyncAndCreds.recordAllowedSocksPass(context, WireGuardManager.sSharedHub.pass);
                        return port;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return probeSharedTunnelOverWgp1(context, profileSig);
    }

    static boolean isHandshakeHealthyNow(Context context, String moduleApkPath) {
        try {
            if (moduleApkPath != null) {
                NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            }
            if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                return Wgbridge.isHandshakeHealthy();
            }
        } catch (Throwable ignored) {
        }
        if (!WireGuardManager.sSharedHub.isOwner && context != null && queryAnyLiveSharedTunnelPort(context) > 0) {
            WireGuardManager.SharedHubSnapshot hub = WireGuardManager.sSharedHub;
            return hub.hsHealthy && hub.lastHsSec > 0L;
        }
        return false;
    }

    static Bundle queryLocalRunningTunnelBundleForProvider(Context ctx, boolean nudgeIfAging) {
        if (ctx == null) {
            return null;
        }
        try {
            String apkPath = ctx.getApplicationInfo() != null ? ctx.getApplicationInfo().sourceDir : null;
            NativeBridgeLoader.ensureLoaded(ctx, apkPath);
            if (!NativeBridgeLoader.isLoaded() || !Wgbridge.isRunning()) {
                return null;
            }
            int port = (int) Wgbridge.getActivePort();
            if (port <= 0) {
                return null;
            }
            WireGuardManager.TunnelStats st = WireGuardManager.getLiveStats(ctx, apkPath);
            boolean hsHealthy = Wgbridge.isHandshakeHealthy();
            long nowSec = System.currentTimeMillis() / 1000L;
            if (nudgeIfAging && (st.lastHandshakeSec <= 0L || Math.max(0L, nowSec - st.lastHandshakeSec) >= WireGuardManager.PROACTIVE_HANDSHAKE_NUDGE_AGE_SEC)) {
                nudgeTunnelHandshakeAsync(ctx, apkPath, null);
            }
            SharedPreferences sp = ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
            WireGuardManager.TunnelConfig cfg = WireGuardManager.getConnectedProfile(ctx, apkPath);
            String sig = sp.getString("sig", "");
            if (sig.isEmpty() && cfg != null && cfg.hasPeerConfigured()) {
                sig = WireGuardManager.safeTrim(cfg.endpoint) + "|" + WireGuardManager.safeTrim(cfg.publicKey);
            }
            String profileId = sp.getString("profileId", "");
            if (profileId.isEmpty() && cfg != null && cfg.id != null) {
                profileId = cfg.id;
            }
            String profileName = sp.getString("profileName", "");
            if (profileName.isEmpty() && cfg != null && cfg.name != null) {
                profileName = cfg.name;
            }
            WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
            String socksUser = !creds.user.isEmpty() ? creds.user : sp.getString("socksUser", "");
            String socksPass = !creds.pass.isEmpty() ? creds.pass : sp.getString("socksPass", "");

            Bundle out = new Bundle();
            out.putInt("port", port);
            out.putString("sig", sig);
            out.putString("owner", ctx.getPackageName());
            out.putString("profileId", profileId);
            out.putString("profileName", profileName);
            out.putString("socksUser", socksUser);
            out.putString("socksPass", socksPass);
            out.putLong("lastHsSec", st.lastHandshakeSec);
            out.putBoolean("hsHealthy", hsHealthy);
            out.putLong("updatedAt", System.currentTimeMillis());
            return out;
        } catch (Throwable ignored) {
            return null;
        }
    }

    static void nudgeTunnelHandshakeAsync(final Context context, final String moduleApkPath, final Runnable onUpdatedMain) {
        if (context == null) {
            return;
        }
        long nowElapsed = SystemClock.elapsedRealtime();
        if ((nowElapsed - WireGuardManager.sLastHandshakeNudgeMs) < 2500L
                || !WireGuardManager.sHandshakeNudgeInFlight.compareAndSet(false, true)) {
            return;
        }
        WireGuardManager.sLastHandshakeNudgeMs = nowElapsed;
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        WireGuardManager.SYNC_EXEC.execute(() -> {
            try {
                try {
                    NativeBridgeLoader.ensureLoaded(appCtx, moduleApkPath);
                } catch (Throwable ignored) {
                }
                if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                    Wgbridge.ensureTunnelAlive(1800L);
                    int p = (int) Wgbridge.getActivePort();
                    WireGuardManager.TunnelConfig cfg = WireGuardManager.getConnectedProfile(appCtx, moduleApkPath);
                    if (p > 0) {
                        String sig = (cfg != null && cfg.hasPeerConfigured())
                                ? (WireGuardManager.safeTrim(cfg.endpoint) + "|" + WireGuardManager.safeTrim(cfg.publicKey))
                                : "";
                        WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
                        registerSharedTunnel(
                                appCtx,
                                p,
                                sig,
                                cfg != null ? cfg.id : WireGuardManager.sConnectedProfileId,
                                cfg != null ? cfg.name : "",
                                creds.user,
                                creds.pass
                        );
                    }
                } else {
                    try {
                        appCtx.getContentResolver().call(
                                Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                                KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                                "nudge",
                                null
                        );
                    } catch (Throwable ignored) {
                    }
                    WireGuardManager.sLastSharedHubCheckMs = 0L;
                    int p = queryAnyLiveSharedTunnelPort(appCtx);
                    long nowSec = System.currentTimeMillis() / 1000L;
                    long lastSharedHs = WireGuardManager.sSharedHub.lastHsSec;
                    if (p > 0 && (lastSharedHs <= 0L || Math.max(0L, nowSec - lastSharedHs) >= 135L)) {
                        try (Socket ignoredSock = WgTunnelProber.openSocks5Ipv4Socket(
                                p,
                                WgSyncAndCreds.getActiveSocksUser(),
                                WgSyncAndCreds.getActiveSocksPass(appCtx),
                                new byte[]{1, 1, 1, 1},
                                443,
                                1800
                        )) {
                            // Deliberately trigger Go awaitHandshakeReadyOrFail on owning mux process.
                        } catch (Throwable ignored) {
                        }
                        try {
                            Thread.sleep(350L);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                        WireGuardManager.sLastSharedHubCheckMs = 0L;
                        queryAnyLiveSharedTunnelPort(appCtx);
                    }
                }
            } catch (Throwable ignored) {
            } finally {
                WireGuardManager.sHandshakeNudgeInFlight.set(false);
                if (onUpdatedMain != null) {
                    new Handler(Looper.getMainLooper()).post(onUpdatedMain);
                }
            }
        });
    }

    static long getSharedTunnelLastHandshakeSec(Context context) {
        try {
            if (context != null) {
                NativeBridgeLoader.ensureLoaded(context, null);
            }
            if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                WireGuardManager.TunnelStats st = WireGuardManager.getLiveStats(context, null);
                long nowSec = System.currentTimeMillis() / 1000L;
                if (st.lastHandshakeSec > 0L && Math.max(0L, nowSec - st.lastHandshakeSec) < WireGuardManager.HANDSHAKE_HEALTHY_WINDOW_SEC) {
                    return st.lastHandshakeSec;
                }
            }
        } catch (Throwable ignored) {
        }
        if (context == null) {
            return 0L;
        }
        long nowSec = System.currentTimeMillis() / 1000L;
        WireGuardManager.SharedHubSnapshot prevHub = WireGuardManager.sSharedHub;
        if (prevHub.lastHsSec <= 0L
                || Math.max(0L, nowSec - prevHub.lastHsSec) >= WireGuardManager.PROACTIVE_HANDSHAKE_NUDGE_AGE_SEC
                || (SystemClock.elapsedRealtime() - WireGuardManager.sLastSharedHubCheckMs) >= 2000L) {
            WireGuardManager.sLastSharedHubCheckMs = 0L;
        }
        int livePort = queryAnyLiveSharedTunnelPort(context);
        if (livePort > 0) {
            WireGuardManager.SharedHubSnapshot curHub = WireGuardManager.sSharedHub;
            if (curHub.lastHsSec > 0L) {
                return curHub.lastHsSec;
            }
            if (curHub.hsHealthy) {
                return nowSec;
            }
        }
        try {
            int port = -1;
            long updatedAt = 0L;
            long lastHsSec = 0L;
            boolean hsHealthy = false;
            String myPkg = context.getPackageName();
            if ("org.telegram.wgplus.module".equals(myPkg)) {
                SharedPreferences sp = context.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
                port = sp.getInt("port", -1);
                updatedAt = sp.getLong("updatedAt", 0L);
                lastHsSec = sp.getLong("lastHsSec", 0L);
                hsHealthy = sp.getBoolean("hsHealthy", false);
            } else {
                Bundle out = context.getContentResolver().call(
                        Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                        KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                        null,
                        null
                );
                if (out != null) {
                    port = out.getInt("port", -1);
                    updatedAt = out.getLong("updatedAt", 0L);
                    lastHsSec = out.getLong("lastHsSec", 0L);
                    hsHealthy = out.getBoolean("hsHealthy", false);
                }
            }
            if (port > 0 && (updatedAt <= 0L || Math.abs(System.currentTimeMillis() - updatedAt) < 300_000L)) {
                WireGuardManager.SharedHubSnapshot cur = WireGuardManager.sSharedHub;
                if (!cur.isOwner) {
                    int effPort = cur.port > 0 ? cur.port : port;
                    WireGuardManager.updateSharedHubClient(effPort, cur.user, cur.pass, lastHsSec, hsHealthy);
                }
                return (hsHealthy && lastHsSec > 0L) ? lastHsSec : 0L;
            }
        } catch (Throwable ignored) {
        }
        return 0L;
    }

    static void registerSharedTunnel(
            Context context,
            int port,
            String profileSig,
            String profileId,
            String profileName,
            String socksUser,
            String socksPass
    ) {
        if (context == null || port <= 0) return;
        try {
            long lastHsSec = 0L;
            boolean hsHealthy = false;
            try {
                if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                    hsHealthy = Wgbridge.isHandshakeHealthy();
                    WireGuardManager.TunnelStats st = WireGuardManager.getLiveStats(context, null);
                    lastHsSec = st.lastHandshakeSec;
                    if (!hsHealthy) {
                        lastHsSec = 0L;
                    }
                }
            } catch (Throwable ignored) {
            }
            Bundle b = new Bundle();
            b.putInt("port", port);
            b.putString("sig", profileSig != null ? profileSig : "");
            b.putString("owner", context.getPackageName());
            b.putString("profileId", profileId != null ? profileId : "");
            b.putString("profileName", profileName != null ? profileName : "");
            b.putString("socksUser", socksUser != null ? socksUser : "");
            b.putString("socksPass", socksPass != null ? socksPass : "");
            b.putLong("lastHsSec", lastHsSec);
            b.putBoolean("hsHealthy", hsHealthy);
            context.getContentResolver().call(
                    Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                    KeepaliveStatusProvider.METHOD_REGISTER_SHARED_TUNNEL,
                    null,
                    b
            );
            WireGuardManager.sLastSharedTunnelHeartbeatMs = System.currentTimeMillis();
        } catch (Throwable ignored) {
        }
    }

    static void clearSharedTunnel(Context context) {
        clearSharedTunnelForPort(context, -1);
    }

    static void clearSharedTunnelForPort(Context context, int onlyPort) {
        if (context == null) return;
        try {
            Bundle b = new Bundle();
            b.putString("owner", context.getPackageName());
            if (onlyPort > 0) {
                b.putInt("port", onlyPort);
            }
            context.getContentResolver().call(
                    Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                    KeepaliveStatusProvider.METHOD_CLEAR_SHARED_TUNNEL,
                    null,
                    b
            );
        } catch (Throwable ignored) {
        }
    }

    static Bundle fetchSharedHubInfoBundle(Context context) {
        if (context == null) {
            return null;
        }
        try {
            String myPkg = context.getPackageName();
            if ("org.telegram.wgplus.module".equals(myPkg)) {
                SharedPreferences sp = context.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
                Bundle b = new Bundle();
                b.putInt("port", sp.getInt("port", -1));
                b.putString("owner", sp.getString("owner", ""));
                b.putString("socksUser", sp.getString("socksUser", ""));
                b.putString("socksPass", sp.getString("socksPass", ""));
                b.putLong("lastHsSec", sp.getLong("lastHsSec", 0L));
                b.putBoolean("hsHealthy", sp.getBoolean("hsHealthy", false));
                b.putLong("updatedAt", sp.getLong("updatedAt", 0L));
                b.putBoolean("daemonOrRootActive",
                        PrivilegeBridge.isStandaloneDaemonAlive(context)
                                || PrivilegeBridge.isRootAvailablePassive(context));
                return b;
            }
            if (Looper.myLooper() == Looper.getMainLooper()) {
                return null;
            }
            return context.getContentResolver().call(
                    WireGuardManager.STATUS_PROVIDER_URI,
                    KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                    null,
                    null
            );
        } catch (Throwable ignored) {
            return null;
        }
    }

    static String fetchRemoteEngineDiagnosticsBundle(Context context, String moduleApkPath, int port) {
        if (context == null || port <= 0 || Looper.myLooper() == Looper.getMainLooper()) {
            return "";
        }
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            if (!NativeBridgeLoader.isLoaded()) {
                return "";
            }
            LinkedHashSet<String> passes = new LinkedHashSet<>();
            String snapPass = WireGuardManager.sSharedHub.pass;
            if (!snapPass.isEmpty()) {
                passes.add(snapPass);
            }
            Bundle info = fetchSharedHubInfoBundle(context);
            if (info != null) {
                String sp = info.getString("socksPass", "");
                if (sp != null && !sp.isEmpty()) {
                    passes.add(sp);
                }
            }
            String activePass = WgSyncAndCreds.getActiveSocksPass(context);
            if (activePass != null && !activePass.isEmpty()) {
                passes.add(activePass);
            }
            for (String p : passes) {
                String res = Wgbridge.requestRemoteDiagnosticsBundleJSON(port, p);
                if (res != null && !res.trim().isEmpty()) {
                    return res;
                }
            }
        } catch (Throwable ignored) {
        }
        return "";
    }
}
