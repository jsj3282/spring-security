package com.example.springsecurity.config.oauth;

import com.example.springsecurity.config.auth.PrincipalDetails;
import com.example.springsecurity.config.oauth.provider.FacebookUserInfo;
import com.example.springsecurity.config.oauth.provider.GoogleUserInfo;
import com.example.springsecurity.config.oauth.provider.NaverUserInfo;
import com.example.springsecurity.config.oauth.provider.OAuth2UserInfo;
import com.example.springsecurity.model.User;
import com.example.springsecurity.repository.UserRepository;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Data
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    //@Autowired
//    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    public BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("ClientRegistration : " + userRequest.getClientRegistration());
        System.out.println("AccessToken : " + userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("Attributes : " + super.loadUser(userRequest).getAttributes());

        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));


        }
        else {
            System.out.println("우리는 구글과 페이스북과 네이버만 지원해요ㅎㅎ");
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String email = oAuth2UserInfo.getEmail();
        String password = bCryptPasswordEncoder.encode("겟인데어");
        System.out.println("password = " + password);
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if (userEntity == null) {
            System.out.println("로그인이 최초입니다.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        } else {
            System.out.println("로그인을 이미 한적이 있습니다. 당신은 자동 회원가입이 되어 있습니다.");
        }

//        return super.loadUser(userRequest);
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
