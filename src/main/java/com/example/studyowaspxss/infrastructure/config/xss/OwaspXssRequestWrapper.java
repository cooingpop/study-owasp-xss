package com.example.studyowaspxss.infrastructure.config.xss;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.owasp.encoder.Encode;
import org.owasp.html.*;

import java.util.HashMap;
import java.util.Map;

/**
 * OWASP Java HTML Sanitizer와 OWASP Java Encoder를 조합하여
 * XSS 보호를 적용하는 사용자 정의 요청 래퍼
 * XSS 공격으로부터 보호하면서도 HTML 콘텐츠를 허용
 * Lucy-XSS 필터 규칙을 OWASP HTML Sanitizer를 사용하여 구현
 *
 * <p>이 버전은 OWASP HTML Sanitizer의 편의성 메서드를 최대한 활용하여 코드를 간결화합니다.</p>
 */
@Slf4j // 로그 사용을 위한 Lombok 어노테이션
public class OwaspXssRequestWrapper extends HttpServletRequestWrapper {

    // 모든 정책을 결합한 최종 정책 (static final로 한 번만 초기화)
    private static final PolicyFactory policyFactory;

    public OwaspXssRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    // static 블록에서 policyFactory를 초기화하여,
    // 인스턴스 생성 시마다 정책을 다시 빌드하는 오버헤드를 줄입니다.
    static {
        // OWASP Sanitizers에서 제공하는 기본 안전 정책들을 조합합니다.
        // Sanitizers.MESSAGES는 존재하지 않으므로 제거합니다.
        PolicyFactory basePolicy = Sanitizers.FORMATTING // b, i, p, br 등 일반적인 텍스트 서식
                .and(Sanitizers.LINKS)      // a 태그, href 등 링크 관련
                .and(Sanitizers.IMAGES)     // img 태그, src 등 이미지 관련
                .and(Sanitizers.BLOCKS)     // div, ul, ol, li 등 블록 요소
                .and(Sanitizers.TABLES)     // table, tr, td 등 테이블 관련
                .and(Sanitizers.STYLES);    // style 속성 (CSS 인젝션 방어 포함)

        // Lucy-XSS 필터의 특정 규칙이나 basePolicy에 포함되지 않는 추가 요소를 정의합니다.
        PolicyFactory customPolicy = new HtmlPolicyBuilder()
                // Sanitizers 기본 정책에 포함되지 않는 폼 관련 요소들을 추가합니다.
                .allowElements(
                        "input", "label", "legend", "textarea", "select", "optgroup", "option",
                        "button", "form", "meter", "output", "progress"
                )
                // 기타 Lucy-XSS에서 허용했으나 Sanitizers 기본 정책에 명시적으로 포함되지 않는 요소들
                .allowElements(
                        "area", "audio", "canvas", "data", "datalist", "del", "details", "dialog", "dir",
                        "fieldset", "figcaption", "figure", "footer", "header", "hr",
                        "main", "map", "menu", "menuitem", "nav",
                        "param", "picture", "pre", "q", "rp", "rt", "ruby", "s", "samp", "section",
                        "source", "strike", "summary", "time", "track", "tt", "u", "var", "video", "wbr"
                )
                // Lucy-XSS에서 비활성화했던 위험한 요소들을 명시적으로 제거합니다. (매우 중요)
                .disallowElements("body", "embed", "iframe", "meta", "object", "script", "link", "base")
                // 추가적인 전역 속성이 필요하면 여기에 정의합니다.
                // class, id, title은 Sanitizers.FORMATTING, BLOCKS 등에 의해 처리될 수 있고,
                // style은 Sanitizers.STYLES에 의해 처리되므로 중복될 수 있습니다.
                // .allowAttributes("class", "id", "title").globally()
                .toFactory();

        // 최종 정책은 기본 정책과 커스텀 정책을 결합한 것입니다.
        policyFactory = basePolicy.and(customPolicy);
    }

    /**
     * 단일 요청 파라미터의 값을 XSS 필터링합니다.
     */
    @Override
    public String getParameter(String name) {
        String value = super.getParameter(name);
        return sanitize(value);
    }

    /**
     * 여러 값을 가지는 요청 파라미터 배열의 값들을 XSS 필터링합니다.
     */
    @Override
    public String[] getParameterValues(String name) {
        String[] values = super.getParameterValues(name);
        if (values == null) {
            return null;
        }
        String[] sanitizedValues = new String[values.length];
        for (int i = 0; i < values.length; i++) {
            sanitizedValues[i] = sanitize(values[i]);
        }
        return sanitizedValues;
    }

    /**
     * 모든 요청 파라미터 맵의 값들을 XSS 필터링합니다.
     */
    @Override
    public Map<String, String[]> getParameterMap() {
        Map<String, String[]> parameterMap = super.getParameterMap();
        Map<String, String[]> sanitizedParameterMap = new HashMap<>();
        for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
            String[] values = entry.getValue();
            String[] sanitizedValues = new String[values.length];
            for (int i = 0; i < values.length; i++) {
                sanitizedValues[i] = sanitize(values[i]);
            }
            sanitizedParameterMap.put(entry.getKey(), sanitizedValues);
        }
        return sanitizedParameterMap;
    }

    /**
     * [핵심] 입력 문자열의 XSS 공격을 방지하기 위해 정화(Sanitize) 또는 인코딩(Encode)을 수행합니다.
     */
    private String sanitize(String value) {
        if (StringUtils.isEmpty(value)) {
            return value;
        }

        // 입력 값에 HTML 태그(<, >)가 포함되어 있는지 확인하여 처리 방식을 결정합니다.
        if (value.contains("<") && value.contains(">")) {
            // HTML 태그가 있는 경우: OWASP HTML Sanitizer를 사용하여 정책에 따라 HTML을 정화합니다.
            String cleanedValue = policyFactory.sanitize(value);
            log.debug("XSS 필터: 원본 값: {}, 정화된 값: {}", value, cleanedValue);
            return cleanedValue;
        } else {
            // HTML 태그가 없는 경우: OWASP Encoder를 사용하여 HTML 컨텍스트에 안전하게 인코딩합니다.
            String encodedValue = Encode.forHtml(value);
            log.debug("XSS 필터: 원본 값: {}, 인코딩된 값: {}", value, encodedValue);
            return encodedValue;
        }
    }
}