package com.example.studyowaspxss.infrastructure.adapter.in.api;

import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * XSS 보호 테스트를 위한 컨트롤러
 * 이 컨트롤러는 XSS 보호 메커니즘을 테스트하기 위한 엔드포인트를 제공합니다
 * 쿼리 파라미터 Sanitizer, 요청 본문 Sanitizer, HTML 콘텐츠 Sanitizer 등을 포함합니다
 */
@RestController
@Slf4j
public class XssTestApiController {

    /**
     * 요청 파라미터에 대한 XSS 보호를 테스트하기 위한 쿼리 파라미터 에코
     * @param input XSS 페이로드를 포함할 수 있는 입력 문자열
     * @return XSS 보호가 적용된 후의 입력 문자열
     */
    @GetMapping("/api/xss-test/echo")
    public ResponseEntity<Map<String, Object>> echoQueryParam(
            @RequestParam String input) {
        // appGroup is already handled by @ApiController annotation
        log.info("XSS 테스트: 쿼리 파라미터 수신: {}", input);
        Map<String, Object> response = new HashMap<>();

        // 정제된 입력 저장
        response.put("original", input);
        response.put("message", "쿼리 파라미터에서 정제된 출력입니다");

        // 입력이 정제되었는지(HTML 정리) 또는 단순히 인코딩되었는지 확인
        // 입력에 &lt; 및 &gt;와 같은 HTML 엔티티가 포함된 경우 인코딩되었을 가능성이 높음
        // 입력에 실제 HTML 태그가 포함된 경우 정제되었을 가능성이 높음
        boolean wasSanitized = input.contains("<") && input.contains(">") && !input.contains("&lt;") && !input.contains("&gt;");
        response.put("isSanitized", wasSanitized);

        return ResponseEntity.ok(response);
    }

    /**
     * JSON 데이터에 대한 XSS 보호를 테스트하기 위한 요청 본문 에코
     * @param request XSS 페이로드를 포함할 수 있는 입력이 포함된 요청
     * @return XSS 보호가 적용된 후의 입력
     */
    @PostMapping("/api/xss-test/echo")
    public ResponseEntity<XssTestResponse> echoRequestBody(
            @RequestBody XssTestRequest request) {
        // appGroup is already handled by @ApiController annotation
        log.info("XSS 테스트: 요청 본문 수신: {}", request.getInput());
        XssTestResponse response = new XssTestResponse();

        String input = request.getInput();
        response.setOriginal(input);
        response.setMessage("요청 본문에서 정제된 출력입니다");

        // 입력이 정제되었는지(HTML 정리) 또는 단순히 인코딩되었는지 확인
        // 입력에 &lt; 및 &gt;와 같은 HTML 엔티티가 포함된 경우 인코딩되었을 가능성이 높음
        // 입력에 실제 HTML 태그가 포함된 경우 정제되었을 가능성이 높음
        boolean wasSanitized = input.contains("<") && input.contains(">") && !input.contains("&lt;") && !input.contains("&gt;");
        response.setSanitized(wasSanitized);

        return ResponseEntity.ok(response);
    }

    /**
     * 입력이 포함된 HTML 콘텐츠 반환
     * @param input XSS 페이로드를 포함할 수 있는 입력 문자열
     * @return 입력이 포함된 HTML 콘텐츠
     */
    @GetMapping("/api/xss-test/html")
    public ResponseEntity<String> returnHtml(
            @RequestParam(required = false) String input) {
        log.info("XSS 테스트: HTML 입력 수신: {}", input);

        // input이 null인 경우 빈 문자열로 처리
        if (input == null) {
            input = "";
        }

        // 입력이 정제되었는지(HTML 정리) 또는 단순히 인코딩되었는지 확인
        // 입력에 &lt; 및 &gt;와 같은 HTML 엔티티가 포함된 경우 인코딩되었을 가능성이 높음
        // 입력에 실제 HTML 태그가 포함된 경우 정제되었을 가능성이 높음
        boolean wasSanitized = input.contains("<") && input.contains(">") && !input.contains("&lt;") && !input.contains("&gt;");

        // 프론트엔드가 추출할 수 있는 메타 태그에 isSanitized 정보 포함
        String html = "<html><head><meta name=\"isSanitized\" content=\"" + wasSanitized + "\"></head>" +
                      "<body><h1>XSS 테스트</h1><p>Your input: " + input + "</p></body></html>";

        return ResponseEntity.ok(html);
    }

    /**
     * XSS 테스트를 위한 요청 클래스
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class XssTestRequest {
        private String input;
    }

    /**
     * XSS 테스트를 위한 응답 클래스
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class XssTestResponse {
        private String original;
        private String message;
        private boolean isSanitized; // HTML이 정제된 경우 true, 단순히 인코딩된 경우 false
    }
}
