# Phantom Lens

A calculator that works like a calculator. Type your secret code and press `=` to open the vault. A wrong code silently takes a photo with the front camera and records the time and place. Photos appear in the **Breach log**, stored only on your own phone. There is no server and the app has no internet permission.

Developed by Hicham Essenouci.

## Use

- Default secret code: `1234`. Change it in Settings.
- A wrong code is a digits-only entry of the same length as your code, followed by `=`, that does not match. Normal arithmetic never triggers a capture.
- Photos are encrypted (AES-256-GCM) with a key held in the Android Keystore, and the app has no internet permission.
- On a wrong code it takes up to three frames and keeps the first one where a face is detected (on-device ML Kit model).
- The home-screen icon and name are a plain calculator (the disguise).
- Use it on your own phone to see who tried to get in. Do not use it on devices or people you have no right to.

## Install

Download `PhantomLens.apk` from the latest [Release](../../releases) and open it on your phone. Android will ask you to allow installs from your browser or file manager.

## Build

Pushing to `main` runs the GitHub Actions workflow, which builds the APK and publishes it as a Release. The logo source is `docs/logo.svg`.
