.class public final Lcom/nc/strdec/StrDec;
.super Ljava/lang/Object;


# static fields
.field private static final GAMMA:J = -0x61c8864680b583ebL

.field private static final SEED:J = 0x5eed000000000000L


# direct methods
.method private constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static d(Ljava/lang/String;)Ljava/lang/String;
    .locals 14

    const/4 v0, 0x2

    :try_start_0
    invoke-static {p0, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object v1

    array-length v2, v1

    const/4 v3, 0x4

    if-ge v2, v3, :cond_0

    goto :goto_1

    :cond_0
    const/4 v2, 0x0

    aget-byte v3, v1, v2

    and-int/lit16 v3, v3, 0xff

    int-to-long v3, v3

    const/16 v5, 0x10

    shl-long/2addr v3, v5

    const/4 v5, 0x1

    aget-byte v5, v1, v5

    and-int/lit16 v5, v5, 0xff

    int-to-long v5, v5

    const/16 v7, 0x8

    shl-long/2addr v5, v7

    or-long/2addr v3, v5

    aget-byte v0, v1, v0

    and-int/lit16 v0, v0, 0xff

    int-to-long v5, v0

    or-long/2addr v3, v5

    array-length v0, v1

    const/4 v5, 0x3

    sub-int/2addr v0, v5

    new-array v6, v0, [B

    :cond_1
    if-ge v2, v0, :cond_2

    int-to-long v8, v2

    add-long/2addr v8, v3

    ushr-long v10, v8, v5

    const-wide v12, -0x61c8864680b583ebL

    mul-long/2addr v10, v12

    const-wide/high16 v12, 0x5eed000000000000L    # 1.854068899003674E149

    add-long/2addr v10, v12

    invoke-static {v10, v11}, Lcom/nc/strdec/StrDec;->mix64(J)J

    move-result-wide v10

    const-wide/16 v12, 0x7

    and-long/2addr v8, v12

    long-to-int v8, v8

    :goto_0
    if-ge v8, v7, :cond_1

    if-ge v2, v0, :cond_1

    mul-int/lit8 v9, v8, 0x8

    ushr-long v12, v10, v9

    long-to-int v9, v12

    add-int/lit8 v12, v2, 0x3

    aget-byte v12, v1, v12

    and-int/lit16 v12, v12, 0xff

    and-int/lit16 v9, v9, 0xff

    xor-int/2addr v9, v12

    int-to-byte v9, v9

    aput-byte v9, v6, v2

    add-int/lit8 v8, v8, 0x1

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    new-instance v0, Ljava/lang/String;

    const-string v1, "UTF-8"

    invoke-direct {v0, v6, v1}, Ljava/lang/String;-><init>([BLjava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object v0

    :catchall_0
    :goto_1
    return-object p0
.end method

.method private static keyByte(JJ)I
    .locals 4

    const/4 v0, 0x3

    ushr-long v0, p2, v0

    const-wide v2, -0x61c8864680b583ebL

    mul-long/2addr v0, v2

    add-long/2addr p0, v0

    invoke-static {p0, p1}, Lcom/nc/strdec/StrDec;->mix64(J)J

    move-result-wide p0

    const-wide/16 v0, 0x7

    and-long/2addr p2, v0

    const-wide/16 v0, 0x8

    mul-long/2addr p2, v0

    long-to-int p2, p2

    ushr-long/2addr p0, p2

    const-wide/16 p2, 0xff

    and-long/2addr p0, p2

    long-to-int p0, p0

    return p0
.end method

.method private static mix64(J)J
    .locals 2

    const/16 v0, 0x1e

    ushr-long v0, p0, v0

    xor-long/2addr p0, v0

    const-wide v0, -0x40a7b892e31b1a47L    # -0.0014818730883930777

    mul-long/2addr p0, v0

    const/16 v0, 0x1b

    ushr-long v0, p0, v0

    xor-long/2addr p0, v0

    const-wide v0, -0x6b2fb644ecceee15L    # -1.981759996145912E-208

    mul-long/2addr p0, v0

    const/16 v0, 0x1f

    ushr-long v0, p0, v0

    xor-long/2addr p0, v0

    return-wide p0
.end method
