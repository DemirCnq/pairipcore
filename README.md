# Pairipcore

In this repository, I explain what I learned from analyzing several applications that use
PairIPCore and how to disable the protection layer. I used AI assistance in some parts of
the analysis and made use of its reports.

---

## 1. Architecture

```text
Process start
  ├─ Manifest: com.pairip.application.Application
  ├─ <clinit> → StartupLauncher.launch() → VMRunner → libpairipcore.so
  └─ attachBaseContext
        ├─ VMRunner.setContext(context)
        ├─ SignatureCheck.verifyIntegrity(context)
        └─ LicenseClient.checkLicense(context)      [depending on the variant]
```

The Java side handles startup, signature verification, and the license flow. The native
side (`libpairipcore.so`) fills placeholder fields, decrypts the `.text` section of some
`.so` files, and runs anti-debug/anti-tamper checks. This is why the app's real string and
`Method` values are not present in the DEX.

### 1.1 Application wrapper

The manifest typically contains the following line:

```xml
<application android:name="com.pairip.application.Application" ...>
```

The PairIP class extends the app's real Application class:

```java
// This code will be different in other applications
package com.pairip.application;

import android.content.Context;
import com.pairip.SignatureCheck;
import com.pairip.VMRunner;
import com.pairip.licensecheck.LicenseClient;

public class Application extends com.example.application {
    @Override
    protected void attachBaseContext(Context context) {
        VMRunner.setContext(context);
        SignatureCheck.verifyIntegrity(context);
        LicenseClient.checkLicense(context);
        super.attachBaseContext(context); // runs `com.example.application`
    }
}
```

- **VMRunner**: loads `libpairipcore.so`, passes the context to the native layer, and runs
  programs in the native VM via `invoke(String programName, Object[] args)`.
- **SignatureCheck**: compares the APK signature with the expected value.
- **LicenseClient**: starts the Play license check; if the license is invalid, it opens a
  paywall via `LicenseActivity` or closes the app.

`StartupLauncher.launch()` can be called from `<clinit>`; in some variants, this also
happens in the real Application class. Depending on the app, the license check is wired
directly into `Application.attachBaseContext`, `LicenseContentProvider.onCreate`, or the
`LicenseActivity`/paywall flow.

**Conclusion:** To disable PairIP, the manifest Application must be changed to the real
class. If there is no real class, `android.app.Application` can be used. However, the real
class's own `<clinit>` may also call `StartupLauncher.launch()`; that call must be no-op'ed
separately.

### 1.2 Startup, native VM, and placeholders

`StartupLauncher.launch()` runs once (the `launchCalled` flag). `VMRunner.<clinit>` calls
`System.loadLibrary("pairipcore")`. The native VM fills String/Method placeholders,
decrypts encrypted libraries with `VmDecryptor`, and performs checks such as
Frida/re-signing detection. When `launch()` is no-op'ed, placeholder fields remain
**null**; when `loadLibrary` is removed, the class loads but the native program does not
run.

Placeholder classes follow this pattern:

```java
package com.example.placeholder;

public final class Alpha {
    public static String stringOne;
    public static String stringTwo;
    // no methods, no instance fields
}
```

Usage: `String key = Alpha.stringOne;`.

Rules: the class has no methods and no instance fields, only `public static` fields; the
types are mostly `String` and `Method`; names look random under real packages; the values
are not in the DEX and are filled by the native VM.

Some method bodies are also moved into the native VM. Only the following call remains on
the Java side:

```smali
const-string/jumbo v1, "nativeProgramName"
invoke-static {v1, v2}, Lcom/pairip/VMRunner;->invoke:(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;
move-result-object v1
return-object v1
```

```java
public static Object nativeProgramName(Object... args) {
    return VMRunner.invoke("nativeProgramName", args);
}
```
Callers that return objects and unbox the result must also be fixed.

### 1.3 License layer

```java
// LicenseActivity works this way in the app I analyzed; this may differ elsewhere
if ("paywall".equals(getIntent().getStringExtra("activitytype")))
    showPaywallAndCloseApp();   // Play Store PendingIntent + closeApp()
else
    showErrorDialog();          // non-dismissible dialog; Close → closeApp()

void closeApp() {
    finishAndRemoveTask();
    System.exit(0);
}
```

### 1.4 Native library encryption

> Native library encryption was not present in the app I analyzed.
> I do not have much information about it.

Some `.so` files have their **`.text`** section encrypted inside the APK. `.rodata`,
`.data`, the symbol table, and the GNU build ID are usually left readable.
`libpairipcore.so` decrypts `.text` in memory. An encrypted library may be a `DT_NEEDED`
dependency of another `.so`.

---

## 2. Bypassing the Protection

Taken from the **original signed APK**.

### 2.1 Changing the manifest Application to the real class

Find the superclass of the PairIP Application from the `.super` line in the Application
smali file. Then edit the manifest:

```diff
- <application android:name="com.pairip.application.Application" ...>
+ <application android:name="com.example.Application" ...>
```

**Warning:** The real Application's `<clinit>` may also call `StartupLauncher.launch()`;
therefore, do not skip the next step.

### 2.2 `StartupLauncher.launch()` → no-op

Before:

```smali
.method public static declared-synchronized launch()V
    .registers 3
    ... monitor-enter / VMRunner.invoke(...) ...
.end method
```

After:

```smali
.method public static declared-synchronized launch()V
    .registers 1

    return-void
.end method
```

No-op'ing `launch()` at a single point is safer than no-op'ing every call individually.

### 2.3 `VMRunner.<clinit>`: loading the native library

Before:

```smali
.method static constructor <clinit>()V
    .registers 1
    const-string v0, "pairipcore"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
```

After:

```smali
.method static constructor <clinit>()V
    .registers 1

    return-void
.end method
```

This prevents `libpairipcore.so` from loading; the native VM, decryption, and anti-tamper
never start.

### 2.4 `VMRunner.invoke()` → null

```smali
.method public static invoke(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;
    .registers 3

    const/4 v0, 0x0

    return-object v0
.end method
```

Remaining `VMRunner.invoke` calls no longer crash and return `null`; calls that return
objects must be reviewed separately.

### 2.5 Call wrappers and object-returning methods

For every `VMRunner.invoke` call, check the caller's return type and any
`move-result-object`, `check-cast`, or unbox usage:

```smali
# Problematic case: invoke returns null, so the caller gets an NPE in Integer.intValue()
const/4 v0, 0x0
return-object v0

# Fixed case: a safe default matching the caller's expected type
const/4 v0, 0x0
invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;
move-result-object v0
return-object v0
```

`V` → `return-void`, `I`/`Z` → `0`/`false`, object → the type expected by the caller.
Void methods such as `onReceive` can be stubbed entirely.

### 2.6 Removing license components

```diff
- <activity android:name="com.pairip.licensecheck.LicenseActivity" ... />
- <provider android:name="com.pairip.licensecheck.LicenseContentProvider" ... />
```

If `LicenseContentProvider` starts `LicenseClient` in `onCreate`, it must be removed. If
the license call is directly in the Application, changing the manifest Application already
skips it.

### 2.7 Placeholder scanning

The candidate class has no methods, no instance fields, only `public static` fields, and
the types are mostly `String`/`Method`. Three examples:

```smali
.class public Lcom/example/placeholder/Alpha;
.super Ljava/lang/Object;
.field public static stringOne:Ljava/lang/String;
.field public static stringTwo:Ljava/lang/String;
# no methods
```

```smali
.class public Lcom/example/placeholder/Beta;
.super Ljava/lang/Object;
.field public static stringThree:Ljava/lang/String;
.field public static stringFour:Ljava/lang/String;
# no methods
```

```smali
.class public Lcom/example/placeholder/Gamma;
.super Ljava/lang/Object;
.field public static methodOne:Ljava/lang/reflect/Method;
# no methods
```

### 2.8 Runtime dump

Values such as static Strings in placeholder classes should be dumped while the original
app is running.

To fix a value, write the dumped value at the read site:

```smali
# Before
sget-object v0, Lcom/example/placeholder/Alpha;->stringOne:Ljava/lang/String;
invoke-virtual {v1, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)...

# After
const-string v0, "example_constant"
invoke-virtual {v1, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)...
```

### 2.9 String patching

Each dumped String value is replaced directly with a `const-string` constant at the
`sget-object` read site. The register stays the same, so the verifier and subsequent code
are unaffected:

```smali
# Before
sget-object v2, Lcom/example/placeholder/Beta;->stringThree:Ljava/lang/String;

# After
const-string v2, "com.example.placeholder.Constant"
```

### 2.10 Native `.text` encryption

> In some applications, native libraries are encrypted.
> I do not have detailed knowledge here; I summarized it from AI reports.

Encrypted `.text` can be recognized as follows:
- the first bytes are not valid instruction starts
- Shannon entropy is higher than normal code (normal ~6.0–6.6, encrypted ~7.8–8.0).

The original signed application is run; after `libpairipcore.so` decrypts `.text` in
memory, the mapped address is found via `/proc/<pid>/maps`, the decrypted bytes are read
via `/proc/<pid>/mem`, and they are written to the **same file offsets** in the original
ELF. The build ID must not change; after writing, `.text` must begin with a valid prologue,
entropy must return to normal, and disassembly must produce meaningful instructions. Only
`.text` should be written, because `.data`/GOT relocations may already be applied in
memory.
