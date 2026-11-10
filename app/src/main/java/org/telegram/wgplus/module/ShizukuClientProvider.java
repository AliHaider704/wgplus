package org.telegram.wgplus.module;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Process;

import moe.shizuku.api.BinderContainer;

/**
 * Standard Shizuku client receiver provider ({@code ${applicationId}.shizuku}) gated by
 * {@code android.permission.INTERACT_ACROSS_USERS_FULL} so {@code shizuku_server} (uid=2000/0)
 * pushes the live {@code IShizukuService} binder directly into this process via {@code sendBinder}.
 */
public class ShizukuClientProvider extends ContentProvider {

    private static final String METHOD_SEND_BINDER = "sendBinder";
    private static final String METHOD_GET_BINDER = "getBinder";
    private static final String EXTRA_BINDER = "moe.shizuku.privileged.api.intent.extra.BINDER";

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        if (method == null) {
            return null;
        }
        if (METHOD_SEND_BINDER.equals(method) && extras != null) {
            extras.setClassLoader(BinderContainer.class.getClassLoader());
            @SuppressWarnings("deprecation")
            BinderContainer container = extras.getParcelable(EXTRA_BINDER);
            if (container != null && container.binder != null) {
                ShizukuBridge.onBinderReceived(getContext(), container.binder);
            }
            return new Bundle();
        }
        if (METHOD_GET_BINDER.equals(method) && Binder.getCallingUid() == Process.myUid()) {
            IBinder binder = ShizukuBridge.peekLiveBinder();
            if (binder == null) {
                return null;
            }
            Bundle reply = new Bundle();
            reply.putParcelable(EXTRA_BINDER, new BinderContainer(binder));
            return reply;
        }
        return new Bundle();
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
