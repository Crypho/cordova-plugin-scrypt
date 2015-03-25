package com.crypho.plugins;

import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

public class ScryptPlugin extends CordovaPlugin {
	private static final String TAG = "Scrypt";
	private static final char[] HEX = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

	static {
    	System.loadLibrary("scrypt_crypho");
    	initialize();
    }

    public static native void initialize();

    public static native void cleanupJNI();

	public native byte[] scrypt(byte[] pass, char[] salt, Integer N, Integer r, Integer p, Integer dkLen);

	@Override
	public boolean execute(String action, CordovaArgs args, final CallbackContext callbackContext) throws JSONException {
		if ("scrypt".equals(action)) {
			String parsedSalt = null;
			final String arg_passphrase = args.getString(0);
			final char[] arg_salt = getSalt(args.get(1));

			JSONObject options = args.getJSONObject(2);
			final Integer N = getIntegerOption("N", options);
			final Integer r = getIntegerOption("r", options);
			final Integer p = getIntegerOption("p", options);
			final Integer dkLen = getIntegerOption("dkLen", options);

			cordova.getThreadPool().execute(new Runnable() {
				public void run() {
					try {
						byte[] passwordBytes = arg_passphrase.getBytes("US-ASCII");
						byte[] res = scrypt(passwordBytes, arg_salt, N, r, p, dkLen);
						String result = hexify(res);
						callbackContext.success(result);
					} catch (Exception e) {
						Log.e(TAG, "Scrypt Failed: " + e.getMessage());
						callbackContext.error(e.getMessage());
					}
				}
			});
			return true;
		}
		return false;
	}

	@Override
	public void finalize() {
		cleanupJNI();
	}

	private String hexify (byte[] input) {
		int len = input.length;
		char[] result = new char[2 * len];
		for ( int j = 0; j < len; j++ ) {
        	int v = input[j] & 0xFF;
        	result[j * 2] = HEX[v >>> 4];
        	result[j * 2 + 1] = HEX[v & 0x0F];
    	}
    	return new String(result).toLowerCase();
	}

	private Integer getIntegerOption(String option, JSONObject options) {
		int arg = options.optInt(option);
		return arg != 0 ? Integer.valueOf(arg) : null;
	}

	private char[] getSalt(Object src){
		if (src instanceof JSONArray) {
			JSONArray tmp = (JSONArray) src;
			int len = tmp.length();
			char[] result = new char[len];
			for (int i = 0; i < len ; i++) {
				result[i] = (char) tmp.optInt(i);
			}
			return result;
		} else {
			return ((String) src).toCharArray();
		}
	}
}