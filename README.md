# PHYchecker

This is a tool based on [Androguard](https://github.com/androguard/androguard) to check if the Activity calling the target sensor correctly closes the listener in `onPause` method.

For more details, please see the [website](https://mobitec.ie.cuhk.edu.hk/phyjacking) about PHYjacking and read [our paper](#) (NDSS'22).

## Run the tool to test your app

### Install requirement

```sh
pip install -r requirements.txt
``` 

### Usage

Here are three python scripts to check these API calls respectively:

|  API   | Sensor Open  | Sensor Close  |File  |
|  ----  | ----  | ----  | ----  |
| FingerprintManager  | .authenticate() | CancellationSignal.cancel() | fingerprint_checker.py |
| Camera2  | .openCamera() | .close() | camera2_checker.py |
| Camera  | .open(), .startPreview() | .release(), .stopPreview() | camera1_checker.py |

Other APIs are easy to extend by following python code:
```
# define your target start and close method
target_start = [('API_CLASS','API_OPEN_METHOD')]
target_close = [('API_CLASS','API_CLOSE_METHOD')]

# create an analyzer instance for one API
analysis = analyzer(dx, target_start, target_close)
result = analysis.jackvul_analysis()
```

Run following command to check `FingerprintManager` API:

```sh
python fingerprint_checker.py test.apk
```

Run for a set of apks (`parallel` required)

```sh
# Note: modify your own path in run_c1.sh first

# run the shell script
./run_camera1.sh
```

Result (of a [fingerprint demo app](https://github.com/pro100svitlo/FingerprintAuthHelper/blob/master/sample/sample-release.apk?raw=true))
```sh
start at:2022-01-11 18:00:26.062744
[*] Analyzing APK ...

[*] constructing call graph ...
number of CG edges: 50872

[*] finding using target method ...
found method: Landroid/hardware/fingerprint/FingerprintManager; -- authenticate
  called by -> Lcom/pro100svitlo/fingerprintAuthHelper/FahManager; -- startListening$fingerprintauthhelper_release
  called by -> Landroid/support/v4/hardware/fingerprint/FingerprintManagerCompatApi23; -- authenticate

[*] finding existing call chain to method ...
   Lcom/pro100svitlo/fingerprintAuthHelper/FahManager$timeOutBroadcast$1; -- onReceive
-> Lcom/pro100svitlo/fingerprintAuthHelper/FahManager; -- startListening$fingerprintauthhelper_release
-> Landroid/hardware/fingerprint/FingerprintManager; -- authenticate

   Landroid/support/v4/hardware/fingerprint/FingerprintManagerCompat$Api23FingerprintManagerCompatImpl; -- authenticate
-> Landroid/support/v4/hardware/fingerprint/FingerprintManagerCompatApi23; -- authenticate
-> Landroid/hardware/fingerprint/FingerprintManager; -- authenticate

   Lcom/pro100svitlo/fingerprintauthdemo/MainActivity; -- onResume
-> Lcom/pro100svitlo/fingerprintAuthHelper/FingerprintAuthHelper; -- startListening
-> Lcom/pro100svitlo/fingerprintAuthHelper/FahManager; -- startListening$fingerprintauthhelper_release
-> Landroid/hardware/fingerprint/FingerprintManager; -- authenticate


[*] finding root class in call chain of target method...
  Lcom/pro100svitlo/fingerprintAuthHelper/FahManager$timeOutBroadcast$1;
  Landroid/support/v4/hardware/fingerprint/FingerprintManagerCompat$Api23FingerprintManagerCompatImpl;
  Lcom/pro100svitlo/fingerprintauthdemo/MainActivity;

[*] finding any interfaces of close ...
found cancel interface: Landroid/support/v4/hardware/fingerprint/FingerprintManagerCompat$FingerprintManagerCompatImpl; -- authenticate

[*] search any activity found in call root ...
found 1 activity in 3 call root class:
  Lcom/pro100svitlo/fingerprintauthdemo/MainActivity;

[*] search onPause in found activity ...

onPause method found in activity or its base class: Lcom/pro100svitlo/fingerprintauthdemo/MainActivity; : Landroid/support/v4/app/FragmentActivity;
inside method onPause
  calling -> Landroid/support/v4/app/BaseFragmentActivityJB; -- onPause
  calling -> Landroid/os/Handler; -- hasMessages
  calling -> Landroid/support/v4/app/FragmentController; -- dispatchPause
  calling -> Landroid/os/Handler; -- removeMessages
  calling -> Landroid/support/v4/app/FragmentActivity; -- onResumeFragments
checking if onPause call any close
close method NOT found in activity or its base class: Lcom/pro100svitlo/fingerprintauthdemo/MainActivity; : Landroid/support/v4/app/FragmentActivity; -- onPause
***this activity is vulnerable!!!***

[*] Result----------------------------
pause-failure
Lcom/pro100svitlo/fingerprintauthdemo/MainActivity;
[*] ----------------------------------

end at:2022-01-11 18:00:37.479751
total time:0:00:11.417007
Maximum Memory Usage: 420.12890625 MB
```
