package com.example.studyowaspxss.infrastructure.config.xss;

import com.fasterxml.jackson.core.SerializableString;
import com.fasterxml.jackson.core.io.CharacterEscapes;
import com.fasterxml.jackson.core.io.SerializedString;
import org.owasp.encoder.Encode;

import java.util.regex.Pattern;

public class HTMLCharacterEscapes extends CharacterEscapes {

    private final int[] asciiEscapes;

    // XSS처리 하지 않기 위한 PATTERN
    // \u00C0-\u017F : LATIN 보충 문자 (라틴 알파벳에 악센트, 변형이 붙은 문자)
    private static final Pattern EXCEPT_PATTERN = Pattern.compile("[\\u00C0-\\u017F]");

    public HTMLCharacterEscapes() {
        // ASCII 문자에 표준 JSON 이스케이프 사용
        asciiEscapes = CharacterEscapes.standardAsciiEscapesForJSON();

        // XSS 에서 가장 중요한 < , > 에 대한 설정
        asciiEscapes['<'] = CharacterEscapes.ESCAPE_CUSTOM;
        asciiEscapes['>'] = CharacterEscapes.ESCAPE_CUSTOM;

         asciiEscapes['('] = CharacterEscapes.ESCAPE_CUSTOM;
         asciiEscapes[')'] = CharacterEscapes.ESCAPE_CUSTOM;
         asciiEscapes['#'] = CharacterEscapes.ESCAPE_CUSTOM;
    }

    @Override
    public int[] getEscapeCodesForAscii() {
        return asciiEscapes;
    }

    @Override
    public SerializableString getEscapeSequence(int ch) {
        String str = Character.toString((char) ch);
        if (isInExceptionPattern((char)ch)) {
            return new SerializedString(str);
        }
        else {
            return new SerializedString(Encode.forHtml(str));
        }
    }

    public static boolean isInExceptionPattern(char character) {
        String str = Character.toString(character);
        return EXCEPT_PATTERN.matcher(str).matches();
    }
}
