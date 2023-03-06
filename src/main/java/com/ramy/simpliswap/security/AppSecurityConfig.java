package com.ramy.simpliswap.security;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig {

    private static final Logger logger = LogManager.getLogger(AppSecurityConfig.class);


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()//Allows restricting access based upon requests using RequestMatchers
                .requestMatchers("/","/home","/login","/fail")//Any request for these endpoints will all be permitted

                .permitAll()

                .anyRequest()//Any other request will have to be authenticated
                .authenticated()
                .and()

                .oauth2Login()
                .loginPage("/login")
                .defaultSuccessUrl("/test")



                .failureUrl("/fail");

        return http.build();

    }



}
