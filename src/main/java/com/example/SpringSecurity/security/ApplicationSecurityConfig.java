package com.example.SpringSecurity.security;

import static com.example.SpringSecurity.security.ApplicationUserPermission.*;
import static com.example.SpringSecurity.security.ApplicationUserRole.ADMIN;
import static com.example.SpringSecurity.security.ApplicationUserRole.ADMIN_TRAINEE;
import static com.example.SpringSecurity.security.ApplicationUserRole.STUDENT;

import com.example.SpringSecurity.student.Student;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;

  @Autowired
  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
//    super.configure(http);
    http
        .csrf().disable()
        .authorizeRequests()
        .antMatchers("/", "index", "/css/*", "/js/*")
        .permitAll()
        .antMatchers("/api/**").hasRole(STUDENT.name())
        .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(HttpMethod.GET, "/management/api/**")
        .hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMIN_TRAINEE.name())
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
