package com.example.studyowaspxss.infrastructure.config.xss;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * OWASP Java HTML Sanitizer와 OWASP Java Encoder를 사용한 XSS 보호 구성
 * 포괄적인 XSS 보호를 위한 Lucy-XSS 필터 규칙 구현
 * 안전한 HTML 콘텐츠를 허용하면서 더 나은 XSS 보호 제공
 */
@Configuration
@Slf4j
@AllArgsConstructor
public class XssConfig implements WebMvcConfigurer {

    private final ObjectMapper objectMapper;

    @Bean
    public FilterRegistrationBean<OwaspXssFilter> filterRegistrationBean() {
        FilterRegistrationBean<OwaspXssFilter> filterRegistration = new FilterRegistrationBean<>();
        filterRegistration.setFilter(new OwaspXssFilter());
        filterRegistration.setOrder(1);
        filterRegistration.addUrlPatterns("/*");
        return filterRegistration;
    }

    @Bean
    public MappingJackson2HttpMessageConverter jsonEscapeConverter() {
        ObjectMapper copy = objectMapper.copy();
        copy.getFactory().setCharacterEscapes(new HTMLCharacterEscapes());
        return new MappingJackson2HttpMessageConverter(copy);
    }

}
