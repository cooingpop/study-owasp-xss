package com.example.studyowaspxss.infrastructure.config.xss;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

/**
 * OWASP Java HTML Sanitizer와 OWASP Java Encoder를 사용한 사용자 정의 XSS 필터
 * 더 이상 사용되지 않는 lucy-xss-filter를 대체
 */
@Slf4j
public class OwaspXssFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        log.info("OwaspXssFilter initialized");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String requestURI = req.getRequestURI();
        String method = req.getMethod();

        log.debug("OwaspXssFilter: 요청 필터링 시작 - URI: {}, Method: {}", requestURI, method);

        // 요청 파라미터 로깅 (디버깅 목적)
        if (log.isDebugEnabled()) {
            req.getParameterMap().forEach((key, values) -> {
                for (String value : values) {
                    if (value != null && (value.contains("<") || value.contains(">"))) {
                        // 잠재적 XSS 콘텐츠 감지 메시지 제거, 값만 로깅
                        log.debug("OwaspXssFilter: 파라미터: {}, 값: {}", key, value);
                    }
                }
            });
        }

        // XSS 보호를 적용하기 위해 요청을 래핑
        OwaspXssRequestWrapper wrappedRequest = new OwaspXssRequestWrapper(req);

        try {
            chain.doFilter(wrappedRequest, response);
            log.debug("OwaspXssFilter: 요청 필터링 완료 - URI: {}", requestURI);
        } catch (Exception e) {
            log.error("OwaspXssFilter: 필터링 중 오류 발생 - URI: {}, 오류: {}", requestURI, e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void destroy() {
        log.info("OwaspXssFilter destroyed");
    }
}
