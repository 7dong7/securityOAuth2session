package org.myoauth.securityoauthsession.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.myoauth.securityoauthsession.dto.CustomOAuth2User;
import org.myoauth.securityoauthsession.dto.GoogleResponse;
import org.myoauth.securityoauthsession.dto.NaverResponse;
import org.myoauth.securityoauthsession.dto.OAuth2Response;
import org.myoauth.securityoauthsession.entity.UserEntity;
import org.myoauth.securityoauthsession.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    // DefaultOAuth2UserService 는 OAuth2UserService 의 구현체
        // OAuth2UserService 을 상속받아서 구현해도 상관없음

    private final UserRepository userRepository;

    // 로그인 완료 Access 토큰으로 리소스 서버에서 유저 정보를 받아온 값을 사용할 메소드
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("oAuth2User: {}", oAuth2User.getAttributes());

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        OAuth2Response oAuth2Response = null;
        if(registrationId.equals("naver")) {

            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());

        } else if (registrationId.equals("google")) {

            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        } else {
            return null;
        }

        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();

        UserEntity existData = userRepository.findByUsername(username);
        String role = null;

        if(existData == null) { // 사용자가 처음 로그인 한 경우

            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setRole("ROLE_USER");

            userRepository.save(userEntity);
        }
        else { // 기존에 로그인한 경우가 있음

            role = existData.getRole();
            existData.setEmail(oAuth2Response.getEmail());

            userRepository.save(existData);
        }

        return new CustomOAuth2User(oAuth2Response, role);
    }
}
