package io.getarrays.securecapita.provider;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import io.getarrays.securecapita.domain.UserPlusItsRoles;
import io.getarrays.securecapita.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.Objects;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static java.lang.System.currentTimeMillis;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;

/**
 * <p>
 * Java class that works with Auth0 Java-JWT tokens maven dependency.
 * </p>
 * <p>
 * After we verify User's login and password, we give him 2 tokens that we will be verify each time he would be trying to do something.
 * </p>
 * <p>
 * There are 2 tokens:
 * <ul>
 * <li>
 * Refresh token - that is needed to return an Access Token
 * </li>
 * <li>
 * Acces Token - we check this to know user's permissions (USER:READ etc)
 * </li>
 * </ul>
 * </p>
 */
@Component
@RequiredArgsConstructor
public class CustomJWTTokenHandler
{

public static final String AUTHORITIES = "authorities";

private static final String GET_ARRAYS_LLC = "GET_ARRAYS_LLC";

private static final String CUSTOMER_MANAGEMENT_SERVICE = "CUSTOMER_MANAGEMENT_SERVICE";

private static final long ACCESS_TOKEN_EXPIRATION_TIME = 432_000_000; //1_800_000;

private static final long REFRESH_TOKEN_EXPIRATION_TIME = 432_000_000; // 5 days

public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";

@Value("${jwt.secret}")
private String secret;

private final UserService userService;



/**
 * Creates Access Token that is needed for accessing web pages on the website
 */
public String createAccessToken(UserPlusItsRoles userPrincipal)
{
    return JWT.create()
              .withIssuer(GET_ARRAYS_LLC)
              .withAudience(CUSTOMER_MANAGEMENT_SERVICE)
              .withIssuedAt(new Date())
              .withSubject(String.valueOf(userPrincipal.getUserDTOPlusItsRole().getId()))
              .withArrayClaim(AUTHORITIES, getClaimsFromUser(userPrincipal))
              .withExpiresAt(new Date(currentTimeMillis() + ACCESS_TOKEN_EXPIRATION_TIME))
              .sign(HMAC512(secret.getBytes()));
}

/**
 * Creates Refresh Token that is needed for getting Access Tokens
 */
public String createRefreshToken(UserPlusItsRoles userPrincipal)
{
    return JWT.create()
              .withIssuer(GET_ARRAYS_LLC)
              .withAudience(CUSTOMER_MANAGEMENT_SERVICE)
              .withIssuedAt(new Date())
              .withSubject(String.valueOf(userPrincipal.getUserDTOPlusItsRole().getId()))
              .withExpiresAt(new Date(currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_TIME))
              .sign(HMAC512(secret.getBytes()));
}

/**
 * <p>
 * Returns id of a User from given token:
 * <ol>
 * <li>
 * Calls this.getJWTVerifier () to create a JWT verifier
 * </li>
 * <li>
 * Asks JWT Verifier to verify given token and get a user's id from token
 * </li>
 * <li>
 * Returns user's id
 * </li>
 * </ol>
 * </p>
 */
public Long getSubject(String token, HttpServletRequest request)
{
    try
    {
        return Long.valueOf(getJWTVerifier().verify(token).getSubject());
    }catch(TokenExpiredException exception)
    {
        request.setAttribute("expiredMessage", exception.getMessage());
        throw exception;
    }catch(InvalidClaimException exception)
    {
        request.setAttribute("invalidClaim", exception.getMessage());
        throw exception;
    }catch(Exception exception)
    {
        throw exception;
    }
}

/**
 * <p>
 * Returns a List of permissions from given token.
 * It is needed for Custom Authorizaton Filter to work:
 * <ol>
 * <li>
 * Calls this.getClaimsFromToken () to get an array of Strings that represents permissions from given token
 * </li>
 * <li>
 * Returns a List of permissions from given token
 * </li>
 * </ol>
 * </p>
 */
public List<GrantedAuthority> getAuthorities(String token)
{
    String[] claims = getClaimsFromToken(token);
    return stream(claims).map(SimpleGrantedAuthority::new).collect(toList());
}

/**
 * Returns Username Password Authentication Token. It is needed for Custom Authorizaton Filter to work
 */
public Authentication getAuthentication(Long userId,
                                        List<GrantedAuthority> authorities,
                                        HttpServletRequest request
)
{
    UsernamePasswordAuthenticationToken userPasswordAuthToken = new UsernamePasswordAuthenticationToken(userService.getUserById(userId),
                                                                                                        null,
                                                                                                        authorities);
    userPasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    return userPasswordAuthToken;
}

/**
 * <p>
 * Checks that given userId is not null AND that token is not expired
 * <ol>
 * <li>
 * Calls this.getJWTVerifier () to create a JWT Verifier
 * </li>
 * <li>
 * Checks that given userId is not null AND that token is not expired
 * </li>
 * <li>
 * Calls this.isTokenExpired to check whether given token is not expired
 * </li>
 * <li>
 * Return true if both stages 2. and 3. returned true
 * </li>
 * </ol>
 * </p>
 */
public boolean isTokenValid(Long userId, String token)
{
    JWTVerifier verifier = getJWTVerifier();
    return !Objects.isNull(userId) && !isTokenExpired(verifier, token);
}

/**
 * Checks whether given token has expired
 */
private boolean isTokenExpired(JWTVerifier verifier, String token)
{
    Date expiration = verifier.verify(token).getExpiresAt();
    return expiration.before(new Date());
}

/**
 * <p>
 * Returns list of Strings that represents user's permissions (User:Read, User:Write, etc)
 * from a user that is bounded with given UserPrincipal:
 * <ol>
 * <li>
 * Calls this.getJWTVerifier () to create a JWT Verifier
 * </li>
 * <li>
 * Returns an array of Strings that represents permissions of a user that is bounded with given UserPrincipal
 * </li>
 * </ol>
 * </p>
 */
private String[] getClaimsFromUser(UserPlusItsRoles userPrincipal)
{
    return userPrincipal.getAuthorities().stream().map(GrantedAuthority::getAuthority).toArray(String[]::new);
}

/**
 * <p>
 * Returns list of Strings that represents permissions from given token:
 * <ol>
 * <li>
 * Calls this.getJWTVerifier () to create a JWT Verifier
 * </li>
 * <li>
 * Returns an array of Strings that represents permissions from token
 * </li>
 * </ol>
 * </p>
 */
private String[] getClaimsFromToken(String token)
{
    JWTVerifier verifier = getJWTVerifier();
    return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
}

/**
 * Creates JWT verifier
 */
private JWTVerifier getJWTVerifier()
{
    JWTVerifier verifier;
    try
    {
        Algorithm algorithm = HMAC512(secret);
        verifier = JWT.require(algorithm).withIssuer(GET_ARRAYS_LLC).build();
    }catch(JWTVerificationException exception)
    {
        throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
    }
    return verifier;
}
}
