package org.myoauth.securityoauthsession.config;

import lombok.RequiredArgsConstructor;
import org.myoauth.securityoauthsession.oauth2.CustomClientRegistrationRepo;
import org.myoauth.securityoauthsession.oauth2.CustomOAuth2AuthorizedClientService;
import org.myoauth.securityoauthsession.service.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomClientRegistrationRepo customClientRegistrationRepo;
    private final CustomOAuth2AuthorizedClientService customOAuth2AuthorizedClientService;
    private final JdbcTemplate jdbcTemplate;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 개발환경 에서의 설정
        http.csrf(AbstractHttpConfigurer::disable); // csrf 끄기
        http.formLogin(AbstractHttpConfigurer::disable); // 폼 로그인 끄기
        http.httpBasic(AbstractHttpConfigurer::disable); // http basic 방식 끄기


//        http.oauth2Client() // 이 방식의 경우 각각의 필터 들을 직접 구현하겠다는 뜻

        // oauth2 사용 클라이언트 방식
        http
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .clientRegistrationRepository(customClientRegistrationRepo.clientRegistrationRepository())
                        .authorizedClientService(customOAuth2AuthorizedClientService.authorizedClientService(
                                jdbcTemplate,
                                customClientRegistrationRepo.clientRegistrationRepository()
                        ))
                        .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                                .userService(customOAuth2UserService)
                        )
                );

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/oauth2/**", "/login/**").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }
}
