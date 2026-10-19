package android.util;

/** 仅对拍/桌面 JVM 期使用的 Base64 顶替实现(不进仓库、不进产物)。
 *  与 android.util.Base64.NO_WRAP(=2) 语义一致:标准表、无换行。 */
public final class Base64 {
    public static final int NO_WRAP = 2;

    public static byte[] decode(String s, int flags) {
        return java.util.Base64.getDecoder().decode(s);
    }

    public static String encodeToString(byte[] b, int flags) {
        return java.util.Base64.getEncoder().encodeToString(b);
    }
}
