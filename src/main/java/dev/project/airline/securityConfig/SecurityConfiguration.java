package dev.project.airline.securityConfig;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    private String base_url = "/api/v1";

    private JpaUserDetailsService jpaUserDetailsService;

    public SecurityConfiguration(JpaUserDetailsService userDetailsService) {
            this.jpaUserDetailsService = userDetailsService;
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

            http
                            .cors(withDefaults())
                            .csrf(csrf -> csrf.disable())
                            .formLogin(form -> form.disable())
                            .logout(out -> out
                                            .logoutUrl(base_url + "/logout")
                                            .invalidateHttpSession(true)
                                            .deleteCookies("JSESSIONID"))
                            .authorizeHttpRequests(auth -> auth
                                            .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll() //esto es para poder abrir el link de h2 para base de datos
                                            .requestMatchers(base_url + "/login").hasAnyRole("USER", "ADMIN")// principio de mínimos
                                            .requestMatchers(base_url).permitAll() 
                                            .requestMatchers(HttpMethod.GET, base_url + "/users").permitAll()
                                            .requestMatchers(base_url + "/public").permitAll()
                                            .requestMatchers(base_url + "/private").hasRole("ADMIN")
                                            .anyRequest().authenticated())
                            .userDetailsService(jpaUserDetailsService)
                            .httpBasic(withDefaults())
                            .sessionManagement(session -> session
                                            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)); //para crear las cookies en el navegador

            http.headers(header -> header.frameOptions(frame -> frame.sameOrigin())); //para poder abrir el h2

            return http.build();

    }

   
    //estas lineas es para crear usuarios en memoria, es decir; no es necesario tenerlos en la base de datos para hacer login
    // @Bean 
    // public InMemoryUserDetailsManager userDetailsManager(){
    //     UserDetails user = User.builder()
    //             .username("abdias")
    //             .password("{noop}1234")
    //             .roles("USER")
    //             .build();
        
    //     UserDetails user2 = User.builder()
    //     .username("daniel")
    //     .password("{noop}1234")
    //     .roles("ADMIN")
    //     .build();

    //     Collection<UserDetails> users = new ArrayList<>();
    //     users.add(user);
    //     users.add(user2);

    //     return new InMemoryUserDetailsManager(users);
    // }
}
