package relay;

import java.util.regex.Pattern;

/**
 * Pure helpers for the plaintext-template ("seal on send") workflow, kept free
 * of Burp types so they can be tested without Burp.
 *
 * A plaintext template is an ordinary request whose body is decrypted plaintext
 * and which carries {@link #HEADER} = the bridge ctx_token of the decrypt it
 * came from. Just before such a request leaves Burp, {@link RelayHttpHandler}
 * encrypts and reseals the body with that context and removes the header, so
 * the token never reaches the target.
 */
final class Seal {

    private Seal() {}

    /** Marks a request whose body is plaintext to be sealed on send. */
    static final String HEADER = "X-Tatar-Relay-Template";

    /** Prefix of the note put on messages this extension sealed. */
    static final String NOTE = "[tatar-relay] sealed";

    /** The bridge issues "t-" + 32 lowercase hex characters (128-bit). */
    private static final Pattern TOKEN = Pattern.compile("t-[0-9a-f]{32}");

    static boolean isToken(String value) {
        return value != null && TOKEN.matcher(value.trim()).matches();
    }

    /** One-line, length-bounded preview for a Burp comment column. */
    static String preview(String text, int max) {
        if (text == null) return "";
        // The text is decrypted, attacker-influenced data headed for a UI cell:
        // neutralise control, format (bidi) and line-separator characters.
        String one = text.replaceAll("[\\p{Cc}\\p{Cf}\\u2028\\u2029]", " ")
                .replaceAll("\\s+", " ").trim();
        if (max < 2 || one.length() <= max) return one;
        int cut = max - 1;
        if (Character.isHighSurrogate(one.charAt(cut - 1))) cut--;   // keep pairs whole
        return one.substring(0, cut) + "…";
    }

    /** Note for a request whose body was withheld because sealing failed. */
    static String withheldNote(String why) {
        return "[tatar-relay] seal failed - body withheld: " + preview(why, 200);
    }
}
