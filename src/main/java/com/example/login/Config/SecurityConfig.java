package com.example.login.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
    //기존 보안 기능을 사용자환경에 맞게 변경
    //비밀번호는 일반문자열로 저장을 안한다.
    //비밀번호는 암호로 저장하는게 원칙(암호화한 비밀번호는 되돌리기 기능이 없믐)
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); //Bcrypt 방식으로 암호화처리
    }

    //DB없이 임시계정으로 처리 메모리를 사용
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(){
        UserDetails user = User.builder()
                .username("sample") //사용자 아아디
                .password(passwordEncoder().encode("1234"))//비밀번호
                .roles("USER") //로그인 후 사용권한
                .build(); //생성
        return new InMemoryUserDetailsManager(user);
        }

    //보안 필터링
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        //맵핑에 대한 보안 규칙
        //요청->해당 맵핑별 권한 부여
        //requestMatchers("맵핑명").권한
        //맵핑명 /public/** : public/이후에 모든 맵핑
        //      /public/guest : public/guset 매핑에만 적용
        //permitAll() : 모든 사용자에게 접근 권한
        //authenticated() : 인증된 사용자에게 접근 권한(로그인 성공한 사용자)
        //hasRole("등급") : 해당 등급으로 인증된 사용자에게 접근 권한(ADMIN, USER, GUEST)
        http.authorizeHttpRequests((auth) -> {
            auth.requestMatchers("/").permitAll(); //각 매핑병 권한을 부여(메인페이지는 모든 사용자가 접근 가능
            auth.requestMatchers("/result").authenticated(); //result는 로그인한 사용자만
        });

        //로그인 폼 정보
        //1. loginPage("맵핑명") : 로그인페이지로 이동할 매핑명
        //2. defaultSuccessUrl("매핑명") : 로그인 성공 후 이동할 매핑명
        //3. failureUrl("매핑명") : 로그인 실패시 이동할 매핑명
        //4. usernameParameter("변수명") : html에서 사용하는 사용자 아이디명
        //   <input name="userId"> => usernameParameter("userId")
        //   암호는 반드시 필드명이 password 사용해야 한다.
        //5. permitAll() 등 권한 부여
        return http.build();
    }

}
