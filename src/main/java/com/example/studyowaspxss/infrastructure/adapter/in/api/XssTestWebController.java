package com.example.studyowaspxss.infrastructure.adapter.in.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Slf4j
public class XssTestWebController {

    @GetMapping("/xss-test")
    public String xssTestPage(Model model) {
        log.info("XSS 테스트 페이지 제공");

        return "xss-test";
    }
}
