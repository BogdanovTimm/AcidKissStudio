package io.getarrays.securecapita.configuration;

import io.getarrays.securecapita.filter.CustomAuthorizationFilter;
import io.getarrays.securecapita.handler.CustomAccessDeniedHandler;
import io.getarrays.securecapita.handler.CustomAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig
{



private final BCryptPasswordEncoder encoder;
private final CustomAccessDeniedHandler customAccessDeniedHandler;
private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
private final UserDetailsService userDetailsService;
private final CustomAuthorizationFilter customAuthorizationFilter;
private static final String[] PUBLIC_URLS = {"/api/v1/user/verify/password/**",
                                             "/api/v1/user/login/**",
                                             "/api/v1/user/verify/code/**",
                                             "/api/v1/user/register/**",
                                             "/api/v1/user/resetpassword/**",
                                             "/api/v1/user/verify/account/**",
                                             "/api/v1/user/refresh/token/**",
                                             "/api/v1/user/image/**",
                                             "/api/v1/user/new/password/**",
                                             // #
                                             "/#/api/v1/user/verify/password/**",
                                             "/#/api/v1/user/login/**",
                                             "/#/api/v1/user/verify/code/**",
                                             "/#/api/v1/user/register/**",
                                             "/#/api/v1/user/resetpassword/**",
                                             "/#/api/v1/user/verify/account/**",
                                             "/#/api/v1/user/refresh/token/**",
                                             "/#/api/v1/user/image/**",
                                             "/#/api/v1/user/new/password/**",
                                             "/#/**",
                                             "/#/login/**",
                                             "/#/register/**",
                                             "/**",
                                             "/login/**",
                                             "/register/**"
};

/**
 * <p>
 * Sets:
 * <ul>
 * <li>
 * CSRF
 * </li>
 * <li>
 * CORS
 * </li>
 * <li>
 * Webpages that can be seen without signing in
 * </li>
 * <li>
 * Permissions for HTTP-Methods for some webpages
 * </li>
 * <li>
 * Custom handler for Access Denied Error
 * </li>
 * <li>
 * Custom handler for non-logged user
 * </li>
 * <li>
 * Custom filter that checks every HTTP-request
 * </li>
 * </ul>
 * </p>
 */
@Bean
public SecurityFilterChain filterChain(HttpSecurity http)
                                                          throws Exception
{
    http.csrf(csrf->csrf.disable()) // We disable csrf because in REST API we don't need ti
        .cors(withDefaults());
    http.sessionManagement(session->session.sessionCreationPolicy(STATELESS));
    http.authorizeHttpRequests(request->request.requestMatchers(PUBLIC_URLS).permitAll());
    http.authorizeHttpRequests(request->request.requestMatchers(OPTIONS).permitAll());
    http.authorizeHttpRequests(request->request.requestMatchers(DELETE,
                                                                "/api/v1/user/delete/**")
                                               .hasAuthority("DELETE:USER"));
    http.authorizeHttpRequests(request->request.requestMatchers(DELETE,
                                                                "/api/v1/customer/delete/**")
                                               .hasAuthority("DELETE:CUSTOMER"));
    http.exceptionHandling(exception->exception.accessDeniedHandler(customAccessDeniedHandler) // Sets custom handler for Access Denied Error
                                               .authenticationEntryPoint(customAuthenticationEntryPoint)); // Sets custom handler for non-logged user
    http.addFilterBefore(customAuthorizationFilter, UsernamePasswordAuthenticationFilter.class); // Adds filter that checks user's permissions for every HTTP-Request
    http.authorizeHttpRequests(request->request.anyRequest()
                                               .authenticated()
    );
    System.out.println("CORS was checked");
    return http.build();
}



/**
 * Sets encoder for User's passwords
 */
@Bean
public AuthenticationManager authenticationManager()
{
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService);
    authProvider.setPasswordEncoder(encoder);
    return new ProviderManager(authProvider);
}
}
