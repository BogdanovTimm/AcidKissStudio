package io.getarrays.securecapita.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getarrays.securecapita.domain.HttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.OutputStream;

import static java.time.LocalDateTime.now;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 Custom Exception for Authentication exception.
 It occurs when user has not signed in.
 It outputs JSON code as an HTTP-Response
 */
@Component
public class CustomAuthenticationEntryPoint
        implements AuthenticationEntryPoint
{
    
    @Override
    public void commence (HttpServletRequest request,
                          HttpServletResponse response,
                          AuthenticationException authException
                         )
    throws IOException, ServletException
    {
        HttpResponse httpResponse = HttpResponse.builder ()
                                                .timeStamp (now ().toString ())
                                                .reason ("You need to log in to access this resource")
                                                .status (UNAUTHORIZED)
                                                .statusCode (UNAUTHORIZED.value ())
                                                .build ();
        response.setContentType (APPLICATION_JSON_VALUE);
        response.setStatus (UNAUTHORIZED.value ());
        OutputStream out = response.getOutputStream ();
        ObjectMapper mapper = new ObjectMapper ();
        mapper.writeValue (out, httpResponse);
        out.flush ();
    }
}
















