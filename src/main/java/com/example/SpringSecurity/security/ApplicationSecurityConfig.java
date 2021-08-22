package com.example.SpringSecurity.security;

import static com.example.SpringSecurity.security.ApplicationUserPermission.*;
import static com.example.SpringSecurity.security.ApplicationUserRole.*;
import static com.example.SpringSecurity.security.ApplicationUserRole.ADMIN;
import static com.example.SpringSecurity.security.ApplicationUserRole.ADMIN_TRAINEE;
import static com.example.SpringSecurity.security.ApplicationUserRole.STUDENT;

import com.example.SpringSecurity.filters.CsrfLoggerFilter;
import com.example.SpringSecurity.student.Student;
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
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;

  @Autowired
  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
//        .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//        .and()
        .authorizeRequests()
        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
        .antMatchers("/api/**").hasRole(STUDENT.name())
        .anyRequest()
        .authenticated()
        .and()
        .httpBasic();
  }

  @Override
  @Bean
  protected UserDetailsService userDetailsService() {
    UserDetails annaUser = User.builder()
        .username("anna")
        .password(passwordEncoder.encode("pass"))
//        .roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
        .authorities(STUDENT.getGrantedAuthorities())
        .build();

    UserDetails lindaUser = User.builder()
        .username("linda")
        .password(passwordEncoder.encode("pass"))
//        .roles(ApplicationUserRole.ADMIN.name())
        .authorities(ADMIN.getGrantedAuthorities())
        .build();

    UserDetails tomUser = User.builder()
        .username("tom")
        .password(passwordEncoder.encode("pass2"))
//        .roles(ApplicationUserRole.ADMIN_TRAINEE.name())
        .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
        .build();

    return new InMemoryUserDetailsManager(annaUser, lindaUser, tomUser);
  }
}
