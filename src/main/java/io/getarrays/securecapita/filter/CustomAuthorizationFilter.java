package io.getarrays.securecapita.filter;

import io.getarrays.securecapita.provider.CustomJWTTokenHandler;
import io.getarrays.securecapita.utils.ExceptionUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static io.getarrays.securecapita.utils.ExceptionUtils.processError;
import static java.util.Arrays.asList;
import static java.util.Optional.ofNullable;
import static org.apache.commons.lang3.StringUtils.EMPTY;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * Custom filter, that allows or denies HTTP-Requests for user, based on his permissions
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CustomAuthorizationFilter
                                       extends
                                       OncePerRequestFilter // This means that this filter will be called only once for each HTTP_Request
{

private static final String TOKEN_PREFIX = "Bearer ";

/**
 * A list of URLs without [**] (or they will not work)
 */
private static final String[] PUBLIC_ROUTES = {"/api/v1/user/new/password",
                                               "/api/v1/user/login",
                                               "/api/v1/user/verify/code",
                                               "/api/v1/user/register",
                                               "/api/v1/user/refresh/token",
                                               "/api/v1/user/image",
                                               // #
                                               "/#/api/v1/user/new/password",
                                               "/#/api/v1/user/login",
                                               "/#/api/v1/user/verify/code",
                                               "/#/api/v1/user/register",
                                               "/#/api/v1/user/refresh/token",
                                               "/#/api/v1/user/image",
                                               "/#",
                                               "/#/login",
                                               "/#/register"
};

private static final String HTTP_OPTIONS_METHOD = "OPTIONS";

private final CustomJWTTokenHandler customJWTTokenHandler;



/**
 * <p>
 * Checks every HTTP-Request:
 * <ol>
 * <li>
 * Calls this.getToken () to get JWT-Access Token from given HTTP-Reques
 * </li>
 * <li>
 * Class this.getUserId () to get id of a User that has sent current HTTP-Request
 * </li>
 * <li>
 * Asks TokenProvider to check whether user's id exist
 * AND JWT-Access Token has not expired
 * </li>
 * <li>
 * Asks TokenProvider to return permissions from given JWT-Access Token
 * </li>
 * <li>
 * Asks TokenProvider to return UsernamePasswordAuthenticationToken
 * </li>
 * <li>
 * Asks SecurityContextHolder to authenticate user
 * </li>
 * </ol>
 * </p>
 */
@Override
protected void doFilterInternal(HttpServletRequest request,
                                HttpServletResponse response,
                                FilterChain filter)
                                                    throws ServletException,
                                                    IOException
{
    try
    {
        String token = getToken(request);
        Long userId = getUserId(request);
        if(customJWTTokenHandler.isTokenValid(userId, token))
        {
            List<GrantedAuthority> authorities = customJWTTokenHandler.getAuthorities(token);
            Authentication authentication = customJWTTokenHandler.getAuthentication(userId, authorities, request);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }else
        {
            SecurityContextHolder.clearContext();
        }
        filter.doFilter(request, response);
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        ExceptionUtils.processError(request, response, exception);
    }
}

/**
 * Checker for every HTTP-Request: whether HTTP-Request needs to be checked further by this CustomAuthorizaitonFilter
 */
@Override
protected boolean shouldNotFilter(HttpServletRequest request)
                                                              throws ServletException
{
    return request.getHeader(AUTHORIZATION) == null ||
           !request.getHeader(AUTHORIZATION)
                   .startsWith(TOKEN_PREFIX) ||
           request.getMethod()
                  .equalsIgnoreCase(HTTP_OPTIONS_METHOD) ||
           asList(PUBLIC_ROUTES).contains(request.getRequestURI());
}

/**
 * <p>
 * Returns User's id:
 * <ol>
 * <li>
 * Calls this.getToken () to get JWT-Access Token
 * </li>
 * <li>
 * Asks Token Provider to get user's id from given JWT-Access Token
 * </li>
 * <li>
 * Returns User's id
 * </li>
 * </ol>
 * </p>
 */
private Long getUserId(HttpServletRequest request)
{
    return customJWTTokenHandler.getSubject(getToken(request), request);
}

/**
 * <p>
 * Get JWT-Access Token from Header of HTTP-Request if it exists:
 * <ol>
 * <li>
 * Gets value from header named Authorizaiton
 * </li>
 * <li>
 * Cheks whether value of Authorization header starts with given TOKEN_PREFIX
 * (Bearer in our case)
 * </li>
 * <li>
 * Deletes TOKEN_PREFIX from value (we need only value, without prefix),
 * so, we have only JWT-Access token
 * </li>
 * <li>
 * Returns a JWT-Access Token as a String
 * </li>
 * </ol>
 * </p>
 */
private String getToken(HttpServletRequest request)
{
    return Optional.ofNullable(request.getHeader(AUTHORIZATION))
                   .filter(header->header.startsWith(TOKEN_PREFIX))
                   .map(token->token.replace(TOKEN_PREFIX, EMPTY))
                   .get();
}
}
