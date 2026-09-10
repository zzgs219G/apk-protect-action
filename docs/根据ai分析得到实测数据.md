.method static constructor <clinit>()V
    .registers 1

    const-string v0, "AA9Buw4="

    invoke-static/range {v0 .. v0}, Lcom/nc/strdec/StrDec;->d(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    sget v0, Lcom/xixin/box/BaseActivity;->$stable:I

    sput v0, Lcom/xixin/box/MainActivity;->$stable:I

    return-void
.end method
