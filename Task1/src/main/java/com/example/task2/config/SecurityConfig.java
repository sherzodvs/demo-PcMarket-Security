package com.example.task2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/api/product/**").hasAnyRole("MODERATOR","ADMIN","OPERATOR")
                .antMatchers(HttpMethod.PUT,"/api/product/**").hasAnyRole("ADMIN", "MODERATOR")
                .antMatchers(HttpMethod.POST,"/api/product/**").hasAnyRole("ADMIN", "MODERATOR")
                .antMatchers("/api/product/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("admin").password(passwordEncoder().encode("root123")).roles("ADMIN").and()
                .withUser("moderator").password(passwordEncoder().encode("root123")).roles("MODERATOR").and()
                .withUser("operator").password(passwordEncoder().encode("root123")).roles("OPERATOR");
    }

}
