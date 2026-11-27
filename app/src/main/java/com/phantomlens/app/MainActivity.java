package com.phantomlens.app;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ContentValues;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import android.graphics.SurfaceTexture;
import android.hardware.Camera;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.location.Location;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.provider.MediaStore;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.InputType;
import android.util.Base64;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.EditText;
import android.widget.Toast;

import com.google.android.gms.tasks.Tasks;
import com.google.mlkit.vision.common.InputImage;
import com.google.mlkit.vision.face.Face;
import com.google.mlkit.vision.face.FaceDetection;
import com.google.mlkit.vision.face.FaceDetector;
import com.google.mlkit.vision.face.FaceDetectorOptions;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Phantom Lens. A WebView shows the designed screens (assets/index.html); this class is the
 * bridge: it checks the secret code, takes the silent front-camera photo on a wrong code (up to
 * three frames, keeping the one with a face), encrypts every photo with a key that never leaves
 * the device's secure hardware, and protects the breach log with the fingerprint.
 */
public class MainActivity extends Activity {

    private static final String DEFAULT_CODE = "1234";
    private static final String KEY_ALIAS = "pl_key";

    private WebView web;
    private SharedPreferences prefs;
    private File dir;
    private final Object lock = new Object();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences("pl", MODE_PRIVATE);
        dir = new File(getFilesDir(), "captures");
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();

        web = new WebView(this);
        web.setBackgroundColor(0xFF000000);
        web.setOverScrollMode(WebView.OVER_SCROLL_NEVER);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setSupportZoom(false);
        s.setBuiltInZoomControls(false);
        web.addJavascriptInterface(new Bridge(), "Android");
        web.loadUrl("file:///android_asset/index.html");
        setContentView(web);

        List<String> need = new ArrayList<>();
        String[] perms = {Manifest.permission.CAMERA,
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION};
        for (String p : perms) {
            if (checkSelfPermission(p) != PackageManager.PERMISSION_GRANTED) need.add(p);
        }
        if (!need.isEmpty()) requestPermissions(need.toArray(new String[0]), 1);
    }

    @Override
    protected void onStop() {
        super.onStop();
        js("window.lock && window.lock()");
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        web.evaluateJavascript("window.goBack ? window.goBack() : false", value -> {
            if (!"true".equals(value)) finish();
        });
    }

    private void js(final String code) {
        runOnUiThread(() -> web.evaluateJavascript(code, null));
    }

    private void toast(final String msg) {
        runOnUiThread(() -> Toast.makeText(this, msg, Toast.LENGTH_SHORT).show());
    }

    // ---------------------------------------------------------------- storage

    private JSONArray readCaps() {
        try {
            return new JSONArray(prefs.getString("caps", "[]"));
        } catch (Exception e) {
            return new JSONArray();
        }
    }

    private void writeCaps(JSONArray a) {
        prefs.edit().putString("caps", a.toString()).apply();
    }

    private static boolean validId(String id) {
        return id != null && id.matches("\\d{1,20}");
    }

    private static String place(JSONObject c) {
        if (!c.optBoolean("hasLoc", false)) return "No location";
        double lat = c.optDouble("lat");
        double lon = c.optDouble("lon");
        return String.format(Locale.US, "%.2f° %s · %.2f° %s",
                Math.abs(lat), lat >= 0 ? "N" : "S", Math.abs(lon), lon >= 0 ? "E" : "W");
    }

    // ---------------------------------------------------------------- encryption (Android Keystore, AES-256-GCM)

    private SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(KEY_ALIAS)) {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            kg.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build());
            return kg.generateKey();
        }
        return (SecretKey) ks.getKey(KEY_ALIAS, null);
    }

    private byte[] encrypt(byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key());
        byte[] iv = c.getIV();
        byte[] ct = c.doFinal(plain);
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return out;
    }

    private byte[] decrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, data, 0, 12));
        return c.doFinal(data, 12, data.length - 12);
    }

    /** Returns the plain JPEG bytes of a capture (encrypted .enc, or an older plain .jpg). */
    private byte[] readImage(String id) throws Exception {
        File enc = new File(dir, id + ".enc");
        if (enc.exists()) return decrypt(Files.readAllBytes(enc.toPath()));
        File jpg = new File(dir, id + ".jpg");
        if (jpg.exists()) return Files.readAllBytes(jpg.toPath());
        return null;
    }

    // ---------------------------------------------------------------- capture

    private double[] lastLocation() {
        try {
            if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED
                    && checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                return null;
            }
            LocationManager lm = (LocationManager) getSystemService(LOCATION_SERVICE);
            Location best = null;
            for (String provider : lm.getProviders(true)) {
                Location l = lm.getLastKnownLocation(provider);
                if (l != null && (best == null || l.getTime() > best.getTime())) best = l;
            }
            return best == null ? null : new double[]{best.getLatitude(), best.getLongitude()};
        } catch (Throwable t) {
            return null;
        }
    }

    /** Rotates upright, scales to at most 1280 px and re-encodes as JPEG. */
    private byte[] prepare(byte[] raw, int rotation) {
        Bitmap bm = BitmapFactory.decodeByteArray(raw, 0, raw.length);
        if (bm == null) return null;
        Matrix m = new Matrix();
        m.postRotate(rotation);
        float sc = Math.min(1f, 1280f / Math.max(bm.getWidth(), bm.getHeight()));
        m.postScale(sc, sc);
        Bitmap r = Bitmap.createBitmap(bm, 0, 0, bm.getWidth(), bm.getHeight(), m, true);
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        r.compress(Bitmap.CompressFormat.JPEG, 90, bo);
        return bo.toByteArray();
    }

    private int countFaces(FaceDetector det, byte[] jpeg) {
        try {
            Bitmap b = BitmapFactory.decodeByteArray(jpeg, 0, jpeg.length);
            List<Face> faces = Tasks.await(det.process(InputImage.fromBitmap(b, 0)), 8, TimeUnit.SECONDS);
            return faces.size();
        } catch (Throwable t) {
            return 0;
        }
    }

    private void captureAsync(final int tries) {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return;
        final boolean silent = prefs.getBoolean("silent", true);
        final boolean wantLoc = prefs.getBoolean("loc", true);
        final long ts = System.currentTimeMillis();
        final double[] loc = wantLoc ? lastLocation() : null;

        new Thread(() -> {
            Camera cam = null;
            FaceDetector det = null;
            try {
                Camera.CameraInfo info = new Camera.CameraInfo();
                int id = -1;
                for (int i = 0; i < Camera.getNumberOfCameras(); i++) {
                    Camera.getCameraInfo(i, info);
                    if (info.facing == Camera.CameraInfo.CAMERA_FACING_FRONT) {
                        id = i;
                        break;
                    }
                }
                if (id < 0) return;
                Camera.getCameraInfo(id, info);
                cam = Camera.open(id);
                try {
                    cam.enableShutterSound(!silent);
                } catch (Throwable ignored) {
                }
                Camera.Parameters p = cam.getParameters();
                Camera.Size best = null;
                for (Camera.Size sz : p.getSupportedPictureSizes()) {
                    if (sz.width <= 2048 && (best == null || sz.width * sz.height > best.width * best.height)) {
                        best = sz;
                    }
                }
                if (best != null) p.setPictureSize(best.width, best.height);
                p.setJpegQuality(92);
                cam.setParameters(p);
                cam.setPreviewTexture(new SurfaceTexture(10));
                cam.startPreview();
                Thread.sleep(800); // let exposure settle

                det = FaceDetection.getClient(new FaceDetectorOptions.Builder()
                        .setPerformanceMode(FaceDetectorOptions.PERFORMANCE_MODE_FAST)
                        .build());

                byte[] chosen = null;
                int faces = 0;
                for (int shot = 0; shot < 3; shot++) {
                    final CountDownLatch latch = new CountDownLatch(1);
                    final byte[][] out = new byte[1][];
                    cam.takePicture(null, null, (data, c) -> {
                        out[0] = data;
                        latch.countDown();
                    });
                    latch.await(6, TimeUnit.SECONDS);
                    if (out[0] == null) break;
                    byte[] jpeg = prepare(out[0], info.orientation);
                    if (jpeg == null) break;
                    int n = countFaces(det, jpeg);
                    if (chosen == null || n > faces) {
                        chosen = jpeg;
                        faces = n;
                    }
                    if (n > 0) break; // a face is in frame, good enough
                    cam.startPreview();
                    Thread.sleep(500);
                }
                if (chosen != null) storeCapture(chosen, ts, tries, loc, faces);
            } catch (Throwable ignored) {
            } finally {
                if (det != null) {
                    try {
                        det.close();
                    } catch (Throwable ignored) {
                    }
                }
                if (cam != null) {
                    try {
                        cam.release();
                    } catch (Throwable ignored) {
                    }
                }
            }
        }).start();
    }

    private void storeCapture(byte[] jpeg, long ts, int tries, double[] loc, int faces) throws Exception {
        Files.write(new File(dir, ts + ".enc").toPath(), encrypt(jpeg));
        JSONObject o = new JSONObject();
        o.put("id", String.valueOf(ts));
        o.put("ts", ts);
        o.put("tries", tries);
        o.put("faces", faces);
        o.put("seen", false);
        if (loc != null) {
            o.put("hasLoc", true);
            o.put("lat", loc[0]);
            o.put("lon", loc[1]);
        } else {
            o.put("hasLoc", false);
        }
        synchronized (lock) {
            JSONArray a = readCaps();
            a.put(o);
            writeCaps(a);
        }
    }

    // ---------------------------------------------------------------- biometrics

    private boolean biometricReady() {
        try {
            BiometricManager bm = (BiometricManager) getSystemService(BIOMETRIC_SERVICE);
            //noinspection deprecation
            return bm != null && bm.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS;
        } catch (Throwable t) {
            return false;
        }
    }

    private void promptBiometric() {
        Executor ex = getMainExecutor();
        BiometricPrompt bp = new BiometricPrompt.Builder(this)
                .setTitle("Unlock")
                .setNegativeButton("Cancel", ex, (d, w) -> js("window.lock()"))
                .build();
        bp.authenticate(new CancellationSignal(), ex, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                js("window.showVault()");
            }

            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                js("window.lock()");
            }
        });
    }

    // ---------------------------------------------------------------- bridge to the page

    private class Bridge {

        @JavascriptInterface
        public String getState() {
            try {
                JSONObject o = new JSONObject();
                o.put("codeLen", prefs.getString("code", DEFAULT_CODE).length());
                o.put("silent", prefs.getBoolean("silent", true));
                o.put("loc", prefs.getBoolean("loc", true));
                o.put("fp", prefs.getBoolean("fp", true));
                o.put("attempts", prefs.getInt("attempts", 1));
                JSONArray src;
                synchronized (lock) {
                    src = readCaps();
                }
                JSONArray out = new JSONArray();
                for (int i = src.length() - 1; i >= 0; i--) { // newest first
                    JSONObject c = src.getJSONObject(i);
                    JSONObject v = new JSONObject();
                    v.put("id", c.getString("id"));
                    v.put("ts", c.getLong("ts"));
                    v.put("tries", c.optInt("tries", 1));
                    v.put("seen", c.optBoolean("seen", false));
                    v.put("place", place(c));
                    out.put(v);
                }
                o.put("captures", out);
                return o.toString();
            } catch (Exception e) {
                return "{}";
            }
        }

        /** Called by the calculator when a code-length number is followed by "=". */
        @JavascriptInterface
        public String verify(String entered) {
            synchronized (lock) {
                String code = prefs.getString("code", DEFAULT_CODE);
                if (code.equals(entered)) {
                    prefs.edit().putInt("wrong", 0).apply();
                    return "ok";
                }
                int wrong = prefs.getInt("wrong", 0) + 1;
                int need = prefs.getInt("attempts", 1);
                if (wrong >= need) {
                    prefs.edit().putInt("wrong", 0).apply();
                    captureAsync(wrong);
                } else {
                    prefs.edit().putInt("wrong", wrong).apply();
                }
                return "wrong";
            }
        }

        @JavascriptInterface
        public void unlock() {
            runOnUiThread(() -> {
                if (prefs.getBoolean("fp", true) && biometricReady()) {
                    promptBiometric();
                } else {
                    js("window.showVault()");
                }
            });
        }

        @JavascriptInterface
        public String photo(String id, int maxW) {
            if (!validId(id)) return "";
            try {
                byte[] bytes = readImage(id);
                if (bytes == null) return "";
                BitmapFactory.Options o = new BitmapFactory.Options();
                o.inJustDecodeBounds = true;
                BitmapFactory.decodeByteArray(bytes, 0, bytes.length, o);
                int sample = 1;
                while (o.outWidth / (sample * 2) >= maxW) sample *= 2;
                BitmapFactory.Options o2 = new BitmapFactory.Options();
                o2.inSampleSize = sample;
                Bitmap bm = BitmapFactory.decodeByteArray(bytes, 0, bytes.length, o2);
                if (bm == null) return "";
                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                bm.compress(Bitmap.CompressFormat.JPEG, 85, bo);
                return "data:image/jpeg;base64," + Base64.encodeToString(bo.toByteArray(), Base64.NO_WRAP);
            } catch (Throwable t) {
                return "";
            }
        }

        @JavascriptInterface
        public void markSeen(String id) {
            if (!validId(id)) return;
            synchronized (lock) {
                try {
                    JSONArray a = readCaps();
                    for (int i = 0; i < a.length(); i++) {
                        JSONObject c = a.getJSONObject(i);
                        if (id.equals(c.optString("id"))) c.put("seen", true);
                    }
                    writeCaps(a);
                } catch (Exception ignored) {
                }
            }
        }

        @JavascriptInterface
        public void deleteCapture(String id) {
            if (!validId(id)) return;
            synchronized (lock) {
                try {
                    JSONArray a = readCaps();
                    JSONArray keep = new JSONArray();
                    for (int i = 0; i < a.length(); i++) {
                        JSONObject c = a.getJSONObject(i);
                        if (!id.equals(c.optString("id"))) keep.put(c);
                    }
                    writeCaps(keep);
                } catch (Exception ignored) {
                }
            }
            //noinspection ResultOfMethodCallIgnored
            new File(dir, id + ".enc").delete();
            //noinspection ResultOfMethodCallIgnored
            new File(dir, id + ".jpg").delete();
        }

        @JavascriptInterface
        public void saveCapture(String id) {
            if (!validId(id)) return;
            try {
                byte[] bytes = readImage(id);
                if (bytes == null) throw new Exception("missing");
                ContentValues v = new ContentValues();
                v.put(MediaStore.Images.Media.DISPLAY_NAME, "PhantomLens_" + id + ".jpg");
                v.put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg");
                v.put(MediaStore.Images.Media.RELATIVE_PATH, "Pictures/PhantomLens");
                Uri uri = getContentResolver().insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, v);
                if (uri == null) throw new Exception("insert failed");
                try (OutputStream os = getContentResolver().openOutputStream(uri)) {
                    os.write(bytes);
                }
                toast("Saved to Pictures/PhantomLens");
            } catch (Throwable t) {
                toast("Could not save the photo");
            }
        }

        @JavascriptInterface
        public void setBool(String key, boolean value) {
            if (key.equals("silent") || key.equals("loc") || key.equals("fp")) {
                prefs.edit().putBoolean(key, value).apply();
            }
        }

        @JavascriptInterface
        public void setAttempts(int n) {
            prefs.edit().putInt("attempts", Math.max(1, Math.min(5, n))).putInt("wrong", 0).apply();
        }

        @JavascriptInterface
        public void changeCode() {
            runOnUiThread(() -> {
                final EditText e = new EditText(MainActivity.this);
                e.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                e.setHint("4 to 9 digits, not starting with 0");
                new AlertDialog.Builder(MainActivity.this)
                        .setTitle("New secret code")
                        .setView(e)
                        .setPositiveButton("Save", (d, w) -> {
                            String v = e.getText().toString();
                            if (v.matches("[1-9]\\d{3,8}")) {
                                prefs.edit().putString("code", v).putInt("wrong", 0).apply();
                                toast("Code updated");
                                js("window.refresh()");
                            } else {
                                toast("Use 4 to 9 digits, not starting with 0");
                            }
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
            });
        }

        @JavascriptInterface
        public void wipe() {
            runOnUiThread(() -> new AlertDialog.Builder(MainActivity.this)
                    .setTitle("Wipe all captures?")
                    .setMessage("Every photo in the breach log will be deleted for good.")
                    .setPositiveButton("Wipe", (d, w) -> {
                        synchronized (lock) {
                            writeCaps(new JSONArray());
                            File[] files = dir.listFiles();
                            if (files != null) {
                                for (File f : files) {
                                    //noinspection ResultOfMethodCallIgnored
                                    f.delete();
                                }
                            }
                        }
                        js("window.refresh()");
                    })
                    .setNegativeButton("Cancel", null)
                    .show());
        }
    }
}
