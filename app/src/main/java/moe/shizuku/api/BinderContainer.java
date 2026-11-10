package moe.shizuku.api;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;

/**
 * Minimal pure-SDK wire-compatible container for Shizuku's {@code BinderContainer} Parcelable
 * returned inside {@code getBinder} bundles from {@code content://moe.shizuku.privileged.api.shizuku}.
 */
public class BinderContainer implements Parcelable {

    public final IBinder binder;

    public BinderContainer(IBinder binder) {
        this.binder = binder;
    }

    protected BinderContainer(Parcel in) {
        this.binder = in.readStrongBinder();
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeStrongBinder(binder);
    }

    public static final Creator<BinderContainer> CREATOR = new Creator<BinderContainer>() {
        @Override
        public BinderContainer createFromParcel(Parcel in) {
            return new BinderContainer(in);
        }

        @Override
        public BinderContainer[] newArray(int size) {
            return new BinderContainer[size];
        }
    };
}
