package com.example.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.springsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * Basic Authentication 은 로그아웃 불가능, 간단한 리퀘스트에만 인가함
     * Ant Matches : index.html 같은 기본적인 공개 화면에 대해 인가(authorization)
     * Application Users : DB에 담아 유저 정보에서 불러올 수 있어야함.
     * 이를 가능하게 하는 것이 userDetailsService 에서 유저 정보(UserDetails)를 받아오는 것.
     * 하지만, userDetails 상태로 service에 등록하게되면, 비밀번호는 null 상태를 유지하게됨.
     * 이에 대해 encoding 작업을 거쳐야하고, 이를 PasswordEncoder가 도와준다.
     * Spring boot에서 제공하는 인코딩 방식은 다음과 같다.
     * ► BCryptPasswordEncoder
     * ► Pbkdf2PasswordEncoder
     * ► Argon2PasswordEncoder
     * ► DelegatingPasswordEncoder
     * ► SCryptPasswordEncoder 등
     * <p>
     * 선택
     */

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index", "/css/**", "/js/**").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails parkUser = User.builder()
                .username("park")
                .password(passwordEncoder.encode("1234"))
                .roles(STUDENT.name()) // ROLE_STUDENT
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("12345"))
                .roles(ADMIN.name()) // ROLE_ADMIN
                .build();

        return new InMemoryUserDetailsManager(
                parkUser, lindaUser
        );
    }
}
