package org.telegram.wgplus.module;

import java.lang.reflect.Field;

/**
 * Executed via {@code /system/bin/app_process} in {@code uid=2000} shell domain through Shizuku
 * to resolve hidden platform AIDL transaction IDs cleanly without app-domain reflection blocks.
 */
public final class ShizukuProcessHelper {

    public static final String PREFIX = "TX_SET_PROCESS_IMPORTANT=";

    private ShizukuProcessHelper() {
    }

    public static void main(String[] args) {
        try {
            Class<?> stub = Class.forName("android.app.IActivityManager$Stub");
            Field f = stub.getDeclaredField("TRANSACTION_setProcessImportant");
            f.setAccessible(true);
            int code = f.getInt(null);
            System.out.println(PREFIX + code);
        } catch (Throwable t) {
            System.err.println("ERR=" + t);
            System.exit(1);
        }
    }
}
