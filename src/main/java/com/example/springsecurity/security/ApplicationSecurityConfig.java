package com.example.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.springsecurity.security.ApplicationUserPermission.*;
import static com.example.springsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
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
     *
     * 그 다음으로 유저에 대한 ROLE 과 Permission을 구분해주는데, enum type으로 정의하였다.
     * PERMISSION 에 대해선, COURSE WRITE, COURSE READ, STUDENT WRTIE, STUDENT READ로 구분하였다.
     *      *
     * Role 에 대해 STUDENT, ADMIN, ADMINTRAINEE 로 구분하였고
     * 구글 구아바를 이용해 hashSet으로 PERMISSION 을 등록하였다.
     *
     * 이후 UserDetails에 ROLE을 등록하였고, configure에서는 antMatchers를 통해 permission 없이 들어갈 수 있는 경로
     * 각 Authority에 가능한 경로+HttpMethod 에 대해 지정하였다.
     * ✱ 참고로 'antMatchers' 에 대한 어원은 Apache Ant Home 과 Spring AntPathMatcher 에서 사용한 방식으로 비롯됨
     *
     * UserDetails.builder 의 Role의 역할은 입력받은 문자열에 대해 "Role_"을 붙이는 역할을 함.
     * roles은 GrantedAuthority 를 참조하는데 이를 바탕으로 custom 할 수 있다.
     *
     * antMatchers의 순서는 위애서부터 걸러지므로, GET 같은 경우엔 위로 올려 걸러지지 않도록 한다.
     *  Controller에서 @PreAuthorize 애노테이션을 사용할수 있으며, antMathcers를 대체하는 역할을 한다.
     *  annotation을 사용할 경우 @EnableGlobalMethodSecurity(prePostEnabled = true) 를 입력해줘야 인식한다.
     *
     *  ✱ csrf (Cross Site Response Forgery) : 웹 취약점을 이용한 공격 방법 중 하나로, iframe 같은 HTML 요소에
     *  POST, GET 등의 퀴리를 넣어놓고 해당 사이트에 방문하면, 사용자도 모르게 공격을 하게됨. 이에 대한 방어책으로 웹 서버는
     *  유저에게 csrf token 을 제공하고, 이 쿠키를 같이 전송해야만, 사용자의 요청을 받아들여준다.
     *
     *  ✱ basic Auth : HTTPS recommended, Simple And Fast, Can't logout
     *  ✱ Form Based Authentication : Username & password, Standard in most websites, Forms(Full controlled), Can logout
     *          HTTPS recommended
     *          Session ID 를 이용하여 사용자를 구분한다. 이는 클라이언트 쿠키에 저장되어 제공됨.
     *          remember-me 기능을 사용할 수 있으며, Session ID 와 다르게 DB에 cookie data 가 저장되어 관리됨
     *          2주간의 디폴트 저장기간을 갖는다. 쿠키엔 username, md5 hash of the above 2 values 를 내부에 저장함
     *          logout() method : clearAuthentication, invalidateHttpSession 를 사용하여
     *          내부 쿠키를 삭제할 수 있음. deleteCookies 파라미터로 CookiesName 을 입력해주면 됨
     *          이후 logoutUrl로 로그아웃 이후 페이지 redirect 가능함.
     *
     */

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
//                .antMatchers("/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name()) // 기본 GET
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .anyRequest()
                .authenticated()
                .and()
                .formLogin() // Form Based Authentication(Spring 기본 제공)
                    .loginPage("/login").permitAll()
                    .defaultSuccessUrl("/courses", true)
                    .passwordParameter("passwordxyz")
                    .usernameParameter("username")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverysecured")
                .rememberMeParameter("remember-me")
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                // default 가 csrf로부터 방어하기 위해 POST 로 설정되어있음.
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me")
                .logoutSuccessUrl("/login");


//                .httpBasic();  // basic Auth
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails parkUser = User.builder()
                .username("park")
                .password(passwordEncoder.encode("1234"))
//                .roles(STUDENT.name()) // ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("12345"))
//                .roles(ADMIN.name()) // ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("12345"))
//                .roles(ADMINTRAINEE.name()) // ROLE_ADMIN
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                parkUser, lindaUser, tomUser
        );
    }
}
