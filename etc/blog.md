## Table of contents:
1. <a title="Introduction: JWT Token" href="#introduction">Introduction</a>
2. <a title="pre-requisites" href="#pre-requisites">PRE-requisites</a>
3. <a title="Spring Security: Ajax authentication" href="#ajax-authentication">Ajax authentication</a>
4. <a title="jwt-authentication" href="#jwt-authentication">JWT Authentication</a>

### <a name="introduction" id="introduction">Introduction</a>

This article will guide you on how you can implement JWT authentication with Spring Boot.

We will cover the following two scenarios:

1. Ajax Authentication
2. JWT Token Authentication

### <a name="pre-requisites" id="pre-requisites">PRE-requisites</a>

Please check out the sample code/project from the following GitHub repository: https://github.com/svlada/springboot-security-jwt before going further reading the article.

This project is using H2 in-memory database to store sample user information. To make things easier I have created data fixtures and configured Spring Boot to automatically load them on the application startup (```/jwt-demo/src/main/resources/data.sql```).

Overall project structure is shown below:

```
+---main
|   +---java
|   |   \---com
|   |       \---svlada
|   |           +---common
|   |           +---entity
|   |           +---profile
|   |           |   \---endpoint
|   |           +---security
|   |           |   +---auth
|   |           |   |   +---ajax
|   |           |   |   \---jwt
|   |           |   |       +---extractor
|   |           |   |       \---verifier
|   |           |   +---config
|   |           |   +---endpoint
|   |           |   +---exceptions
|   |           |   \---model
|   |           |       \---token
|   |           \---user
|   |               +---repository
|   |               \---service
|   \---resources
|       +---static
|       \---templates
```

### <a name="ajax-authentication" id="ajax-authentication">Ajax authentication</a>

When we talk about Ajax authentication we usually refer to process where user is supplying credentials through JSON payload that is sent as a part of XMLHttpRequest.

In the first part of this tutorial Ajax authentication is implemented by following standard patterns found in the Spring Security framework.

Following is the list of components that we'll implement:

1. ```AjaxLoginProcessingFilter```
2. ```AjaxAuthenticationProvider```
3. ```AjaxAwareAuthenticationSuccessHandler```
4. ```AjaxAwareAuthenticationFailureHandler```
5. ```RestAuthenticationEntryPoint```
6. ```WebSecurityConfig```

Before we get to the details of the implementation, let's look at the request/response authentication flow.

**Ajax authentication request example**

The Authentication API allows user to pass in credentials in order to receive authentication token.

In our example, client initiates authentication process by invoking Authentication API endpoint (```/api/auth/login```).

Raw HTTP request:

```
POST /api/auth/login HTTP/1.1
Host: localhost:9966
X-Requested-With: XMLHttpRequest
Content-Type: application/json
Cache-Control: no-cache

{
    "username": "svlada@gmail.com",
    "password": "test1234"
}
```

CURL:

```
curl -X POST -H "X-Requested-With: XMLHttpRequest" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -d '{
    "username": "svlada@gmail.com",
    "password": "test1234"
}' "http://localhost:9966/api/auth/login"
```

**Ajax authentication response example**

If client supplied credentials are valid, Authentication API will respond with the HTTP response including the following details:

1. HTTP status "200 OK"
2. Signed JWT Access and Refresh tokens are included in the response body

**JWT Access token** - used to authenticate against protected API resources. It must be set in ```X-Authorization``` header.

**JWT Refresh token** - used to acquire new Access Token. Token refresh is handled by the following API endpoint: ```/api/auth/token```.

Raw HTTP Response:

```
{
  "token": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzdmxhZGFAZ21haWwuY29tIiwic2NvcGVzIjpbIlJPTEVfQURNSU4iLCJST0xFX1BSRU1JVU1fTUVNQkVSIl0sImlzcyI6Imh0dHA6Ly9zdmxhZGEuY29tIiwiaWF0IjoxNDcyMDMzMzA4LCJleHAiOjE0NzIwMzQyMDh9.41rxtplFRw55ffqcw1Fhy2pnxggssdWUU8CDOherC0Kw4sgt3-rw_mPSWSgQgsR0NLndFcMPh7LSQt5mkYqROQ",
  
  "refreshToken": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzdmxhZGFAZ21haWwuY29tIiwic2NvcGVzIjpbIlJPTEVfUkVGUkVTSF9UT0tFTiJdLCJpc3MiOiJodHRwOi8vc3ZsYWRhLmNvbSIsImp0aSI6IjkwYWZlNzhjLTFkMmUtNDg2OS1hNzdlLTFkNzU0YjYwZTBjZSIsImlhdCI6MTQ3MjAzMzMwOCwiZXhwIjoxNDcyMDM2OTA4fQ.SEEG60YRznBB2O7Gn_5X6YbRmyB3ml4hnpSOxqkwQUFtqA6MZo7_n2Am2QhTJBJA1Ygv74F2IxiLv0urxGLQjg"
}
```

**JWT Access Token**

JWT Access token can be used for authentication and authorization:

1. Authentication is performed by verifying JWT Access Token signature. If signature proves to be valid, access to requested API resource is granted.
2. Authorization is done by looking up privileges in the **scope** attribute of JWT Access token.

Decoded JWT Access token has three parts: Header, Claims and Signature as shown below:

Header
```

{
    "alg": "HS512"
}
```

Claims
```
{
  "sub": "svlada@gmail.com",
  "scopes": [
    "ROLE_ADMIN",
    "ROLE_PREMIUM_MEMBER"
  ],
  "iss": "http://svlada.com",
  "iat": 1472033308,
  "exp": 1472034208
}
```

Signature (base64 encoded)
```
41rxtplFRw55ffqcw1Fhy2pnxggssdWUU8CDOherC0Kw4sgt3-rw_mPSWSgQgsR0NLndFcMPh7LSQt5mkYqROQ
```

**JWT Refresh Token**

Refresh token is long-lived token used to request new Access tokens. It's expiration time is greater than expiration time of Access token.

In this tutorial we'll use ```jti``` claim to maintain list of blacklisted or revoked tokens. JWT ID(```jti```) claim is defined by [RFC7519](https://tools.ietf.org/html/rfc7519#section-4.1.7) with purpose to uniquely identify individual Refresh token. 

Decoded Refresh token has three parts: Header, Claims and Signature as shown below:

Header
```
{
  "alg": "HS512"
}
```

Claims
```
{
  "sub": "svlada@gmail.com",
  "scopes": [
    "ROLE_REFRESH_TOKEN"
  ],
  "iss": "http://svlada.com",
  "jti": "90afe78c-1d2e-4869-a77e-1d754b60e0ce",
  "iat": 1472033308,
  "exp": 1472036908
}
```

Signature (base64 encoded)
```
SEEG60YRznBB2O7Gn_5X6YbRmyB3ml4hnpSOxqkwQUFtqA6MZo7_n2Am2QhTJBJA1Ygv74F2IxiLv0urxGLQjg
```

#### AjaxLoginProcessingFilter

First step is to extend ```AbstractAuthenticationProcessingFilter``` in order to provide custom processing of Ajax authentication requests.

De-serialization and basic validation of the incoming JSON payload is done in the ```AjaxLoginProcessingFilter#attemptAuthentication``` method. Upon successful validation of the JSON payload authentication logic is delegated to AjaxAuthenticationProvider class.

In case of a successful authentication ```AjaxLoginProcessingFilter#successfulAuthentication``` method is invoked.
In case of failure authentication  ```AjaxLoginProcessingFilter#unsuccessfulAuthentication``` method is invoked.

```language-java
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private static Logger logger = LoggerFactory.getLogger(AjaxLoginProcessingFilter.class);

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    private final ObjectMapper objectMapper;
    
    public AjaxLoginProcessingFilter(String defaultProcessUrl, AuthenticationSuccessHandler successHandler, 
            AuthenticationFailureHandler failureHandler, ObjectMapper mapper) {
        super(defaultProcessUrl);
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.objectMapper = mapper;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
            if(logger.isDebugEnabled()) {
                logger.debug("Authentication method not supported. Request method: " + request.getMethod());
            }
            throw new AuthMethodNotSupportedException("Authentication method not supported");
        }

        LoginRequest loginRequest = objectMapper.readValue(request.getReader(), LoginRequest.class);
        
        if (StringUtils.isBlank(loginRequest.getUsername()) || StringUtils.isBlank(loginRequest.getPassword())) {
            throw new AuthenticationServiceException("Username or Password not provided");
        }

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

        return this.getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
```

#### AjaxAuthenticationProvider

Responsibility of the AjaxAuthenticationProvider class is to:

1. Verify user credentials against database, LDAP or some other system which holds the user data
2. If ```username``` and ```password``` do not match the record in the database authentication exception is thrown
3. Create UserContext and populate it with user data you need (in our case just ```username``` and ```user privileges```)
4. Upon successful authentication delegate creation of JWT Token to ```AjaxAwareAuthenticationSuccessHandler```

```language-java
@Component
public class AjaxAuthenticationProvider implements AuthenticationProvider {
    private final BCryptPasswordEncoder encoder;
    private final DatabaseUserService userService;

    @Autowired
    public AjaxAuthenticationProvider(final DatabaseUserService userService, final BCryptPasswordEncoder encoder) {
        this.userService = userService;
        this.encoder = encoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.notNull(authentication, "No authentication data provided");

        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        User user = userService.getByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        
        if (!encoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Authentication Failed. Username or Password not valid.");
        }

        if (user.getRoles() == null) throw new InsufficientAuthenticationException("User has no roles assigned");
        
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getRole().authority()))
                .collect(Collectors.toList());
        
        UserContext userContext = UserContext.create(user.getUsername(), authorities);
        
        return new UsernamePasswordAuthenticationToken(userContext, null, userContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
```

#### AjaxAwareAuthenticationSuccessHandler

We'll implement AuthenticationSuccessHandler interface that is called when client has been successfully authenticated.

AjaxAwareAuthenticationSuccessHandler class is our custom implementation of AuthenticationSuccessHandler interface. Responsibility of this class is to add JSON payload containing JWT Access and Refresh tokens into the HTTP response body.

```language-java
@Component
public class AjaxAwareAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final ObjectMapper mapper;
    private final JwtTokenFactory tokenFactory;

    @Autowired
    public AjaxAwareAuthenticationSuccessHandler(final ObjectMapper mapper, final JwtTokenFactory tokenFactory) {
        this.mapper = mapper;
        this.tokenFactory = tokenFactory;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        UserContext userContext = (UserContext) authentication.getPrincipal();
        
        JwtToken accessToken = tokenFactory.createAccessJwtToken(userContext);
        JwtToken refreshToken = tokenFactory.createRefreshToken(userContext);
        
        Map<String, String> tokenMap = new HashMap<String, String>();
        tokenMap.put("token", accessToken.getToken());
        tokenMap.put("refreshToken", refreshToken.getToken());

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        mapper.writeValue(response.getWriter(), tokenMap);

        clearAuthenticationAttributes(request);
    }

    /**
     * Removes temporary authentication-related data which may have been stored
     * in the session during the authentication process..
     * 
     */
    protected final void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return;
        }

        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
}
```

Let's focus for a moment on how JWT Access token is created. In this tutorial we are using [Java JWT](https://github.com/jwtk/jjwt) library created by [Stormpath](https://stormpath.com/).

Make sure that ```JJWT``` dependency is included in your ```pom.xml```.

```language-xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>${jjwt.version}</version>
</dependency>
```

We have created factory class (```JwtTokenFactory```) to decouple token creation logic.

Method ```JwtTokenFactory#createAccessJwtToken```  creates signed JWT Access token.

Method ```JwtTokenFactory#createRefreshToken``` creates signed JWT Refresh token.


```language-java
@Component
public class JwtTokenFactory {
    private final JwtSettings settings;

    @Autowired
    public JwtTokenFactory(JwtSettings settings) {
        this.settings = settings;
    }

    /**
     * Factory method for issuing new JWT Tokens.
     * 
     * @param username
     * @param roles
     * @return
     */
    public AccessJwtToken createAccessJwtToken(UserContext userContext) {
        if (StringUtils.isBlank(userContext.getUsername())) 
            throw new IllegalArgumentException("Cannot create JWT Token without username");

        if (userContext.getAuthorities() == null || userContext.getAuthorities().isEmpty()) 
            throw new IllegalArgumentException("User doesn't have any privileges");

        Claims claims = Jwts.claims().setSubject(userContext.getUsername());
        claims.put("scopes", userContext.getAuthorities().stream().map(s -> s.toString()).collect(Collectors.toList()));

        DateTime currentTime = new DateTime();

        String token = Jwts.builder()
          .setClaims(claims)
          .setIssuer(settings.getTokenIssuer())
          .setIssuedAt(currentTime.toDate())
          .setExpiration(currentTime.plusMinutes(settings.getTokenExpirationTime()).toDate())
          .signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
        .compact();

        return new AccessJwtToken(token, claims);
    }

    public JwtToken createRefreshToken(UserContext userContext) {
        if (StringUtils.isBlank(userContext.getUsername())) {
            throw new IllegalArgumentException("Cannot create JWT Token without username");
        }

        DateTime currentTime = new DateTime();

        Claims claims = Jwts.claims().setSubject(userContext.getUsername());
        claims.put("scopes", Arrays.asList(Scopes.REFRESH_TOKEN.authority()));
        
        String token = Jwts.builder()
          .setClaims(claims)
          .setIssuer(settings.getTokenIssuer())
          .setId(UUID.randomUUID().toString())
          .setIssuedAt(currentTime.toDate())
          .setExpiration(currentTime.plusMinutes(settings.getRefreshTokenExpTime()).toDate())
          .signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
        .compact();

        return new AccessJwtToken(token, claims);
    }
}
```

Please note that if you are instantiating Claims object outside of ```Jwts.builder()``` make sure to first invoke ```Jwts.builder()#setClaims(claims)```. Why? Well, if you don't do that, Jwts.builder will, by default, create empty Claims object. What that means? Well if you call ```Jwts.builder()#setClaims()``` after you have set subject with ```Jwts.builder()#setSubject()``` your subject will be lost. Simply new instance of Claims class will overwrite default one created by Jwts.builder().

#### AjaxAwareAuthenticationFailureHandler

AjaxAwareAuthenticationFailureHandler is invoked by ```AjaxLoginProcessingFilter``` in case of authentication failures. You can design specific error messages based on exception type that have occurred during the authentication process.

```language-java
@Component
public class AjaxAwareAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private final ObjectMapper mapper;
    
    @Autowired
    public AjaxAwareAuthenticationFailureHandler(ObjectMapper mapper) {
        this.mapper = mapper;
    }   
    
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException e) throws IOException, ServletException {
        
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        if (e instanceof BadCredentialsException) {
            mapper.writeValue(response.getWriter(), ErrorResponse.of("Invalid username or password", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
        } else if (e instanceof JwtExpiredTokenException) {
            mapper.writeValue(response.getWriter(), ErrorResponse.of("Token has expired", ErrorCode.JWT_TOKEN_EXPIRED, HttpStatus.UNAUTHORIZED));
        } else if (e instanceof AuthMethodNotSupportedException) {
            mapper.writeValue(response.getWriter(), ErrorResponse.of(e.getMessage(), ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
        }

        mapper.writeValue(response.getWriter(), ErrorResponse.of("Authentication failed", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
    }
}

```

### <a name="jwt-authentication" id="jwt-authentication">JWT Authentication</a>

Token based authentication schema's became immensely popular in recent times, as they provide important benefits when compared to sessions/cookies:

1. CORS
2. No need for CSRF protection
3. Better integration with mobile
4. Reduced load on authorization server
5. No need for distributed session store

Some trade-offs have to be made with this approach:

1. More vulnerable to XSS attacks
2. Access token can contain outdated authorization claims (e.g when some of the user privileges are revoked)
3. Access tokens can grow in size in case of increased number of claims
4. File download API can be tricky to implement
5. True statelessness and revocation are mutually exclusive

In this article we'll investigate how JWT's can used for token based authentication.

JWT Authentication flow is very simple: 

1. User obtains Refresh and Access tokens by providing credentials to the Authorization server
2. User sends Access token with each request to access protected API resource
3. Access token is signed and contains user identity (e.g. user id) and authorization claims. 

It's important to note that authorization claims will be included with the Access token. Why is this important? Well, let's say that authorization claims (e.g user privileges in the database) are changed during the life time of Access token. Those changes will not become effective until new Access token is issued. In most cases this is not big issue, because Access tokens are short-lived. Otherwise go with the opaque token pattern.

Before we get to the details of the implementation, let's look the sample request to protected API resource.

**Signed request to protected API resource**

Following pattern should be used when sending access tokens: ```<header-name> Bearer <access_token>```.

In our example for header name (```<header-name>```) we are using ```X-Authorization```.

Raw HTTP request:
```
GET /api/me HTTP/1.1
Host: localhost:9966
X-Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzdmxhZGFAZ21haWwuY29tIiwic2NvcGVzIjpbIlJPTEVfQURNSU4iLCJST0xFX1BSRU1JVU1fTUVNQkVSIl0sImlzcyI6Imh0dHA6Ly9zdmxhZGEuY29tIiwiaWF0IjoxNDcyMzkwMDY1LCJleHAiOjE0NzIzOTA5NjV9.Y9BR7q3f1npsSEYubz-u8tQ8dDOdBcVPFN7AIfWwO37KyhRugVzEbWVPO1obQlHNJWA0Nx1KrEqHqMEjuNWo5w
Cache-Control: no-cache
```

CURL:
```
curl -X GET -H "X-Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzdmxhZGFAZ21haWwuY29tIiwic2NvcGVzIjpbIlJPTEVfQURNSU4iLCJST0xFX1BSRU1JVU1fTUVNQkVSIl0sImlzcyI6Imh0dHA6Ly9zdmxhZGEuY29tIiwiaWF0IjoxNDcyMzkwMDY1LCJleHAiOjE0NzIzOTA5NjV9.Y9BR7q3f1npsSEYubz-u8tQ8dDOdBcVPFN7AIfWwO37KyhRugVzEbWVPO1obQlHNJWA0Nx1KrEqHqMEjuNWo5w" -H "Cache-Control: no-cache" "http://localhost:9966/api/me"
```

Let's see the implementation details. Following are components we need to implement JWT Authentication:

1. JwtTokenAuthenticationProcessingFilter
2. JwtAuthenticationProvider
3. SkipPathRequestMatcher
4. JwtHeaderTokenExtractor
5. BloomFilterTokenVerifier
6. WebSecurityConfig

#### JwtTokenAuthenticationProcessingFilter

JwtTokenAuthenticationProcessingFilter filter is applied to each API (```/api/**```) with exception of the refresh token endpoint (```/api/auth/token```) and login endpoint (```/api/auth/login```).

This filter has the following responsibilities:

1. Check for access token in ```X-Authorization``` header. If Access token is found in the header, delegate authentication to ```JwtAuthenticationProvider``` otherwise throw authentication exception
2. Invokes success or failure strategies based on the outcome of authentication process performed by ```JwtAuthenticationProvider```

Please ensure that ```chain.doFilter(request, response)``` is invoked upon successful authentication. You want processing of the request to advance to the next filter, because very last one filter ```FilterSecurityInterceptor#doFilter``` is responsible to actually invoke method in your controller that is handling requested API resource.

```language-java
public class JwtTokenAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private final AuthenticationFailureHandler failureHandler;
    private final TokenExtractor tokenExtractor;
    
    @Autowired
    public JwtTokenAuthenticationProcessingFilter(AuthenticationFailureHandler failureHandler, 
            TokenExtractor tokenExtractor, RequestMatcher matcher) {
        super(matcher);
        this.failureHandler = failureHandler;
        this.tokenExtractor = tokenExtractor;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        String tokenPayload = request.getHeader(WebSecurityConfig.JWT_TOKEN_HEADER_PARAM);
        RawAccessJwtToken token = new RawAccessJwtToken(tokenExtractor.extract(tokenPayload));
        return getAuthenticationManager().authenticate(new JwtAuthenticationToken(token));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
```

#### JwtHeaderTokenExtractor

JwtHeaderTokenExtractor is very simple class used to extract Authorization token from header. You can extend TokenExtractor interface and provide your custom implementation that will for example extract token from URL.

```language-java
@Component
public class JwtHeaderTokenExtractor implements TokenExtractor {
    public static String HEADER_PREFIX = "Bearer ";

    @Override
    public String extract(String header) {
        if (StringUtils.isBlank(header)) {
            throw new AuthenticationServiceException("Authorization header cannot be blank!");
        }

        if (header.length() < HEADER_PREFIX.length()) {
            throw new AuthenticationServiceException("Invalid authorization header size.");
        }

        return header.substring(HEADER_PREFIX.length(), header.length());
    }
}
```

#### JwtAuthenticationProvider

JwtAuthenticationProvider has the following responsibilities:

1. Verify the access token's signature
2. Extract identity and authorization claims from Access token and use them to create UserContext
3. If Access token is malformed, expired or simply if token is not signed with the appropriate signing key Authentication exception will be thrown

```language-java
@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtSettings jwtSettings;
    
    @Autowired
    public JwtAuthenticationProvider(JwtSettings jwtSettings) {
        this.jwtSettings = jwtSettings;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RawAccessJwtToken rawAccessToken = (RawAccessJwtToken) authentication.getCredentials();

        Jws<Claims> jwsClaims = rawAccessToken.parseClaims(jwtSettings.getTokenSigningKey());
        String subject = jwsClaims.getBody().getSubject();
        List<String> scopes = jwsClaims.getBody().get("scopes", List.class);
        List<GrantedAuthority> authorities = scopes.stream()
                .map(authority -> new SimpleGrantedAuthority(authority))
                .collect(Collectors.toList());
        
        UserContext context = UserContext.create(subject, authorities);
        
        return new JwtAuthenticationToken(context, context.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}

```

#### SkipPathRequestMatcher

JwtTokenAuthenticationProcessingFilter  filter is configured to skip following endpoints: ```/api/auth/login``` and ```/api/auth/token```. This is achieved with ```SkipPathRequestMatcher``` implementation of ```RequestMatcher```.

```language-java
public class SkipPathRequestMatcher implements RequestMatcher {
    private OrRequestMatcher matchers;
    private RequestMatcher processingMatcher;
    
    public SkipPathRequestMatcher(List<String> pathsToSkip, String processingPath) {
        Assert.notNull(pathsToSkip);
        List<RequestMatcher> m = pathsToSkip.stream().map(path -> new AntPathRequestMatcher(path)).collect(Collectors.toList());
        matchers = new OrRequestMatcher(m);
        processingMatcher = new AntPathRequestMatcher(processingPath);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        if (matchers.matches(request)) {
            return false;
        }
        return processingMatcher.matches(request) ? true : false;
    }
}
```

#### WebSecurityConfig

WebSecurityConfig class extends WebSecurityConfigurerAdapter to provide custom security configuration.

Following beans are configured and instantiated in this class:

1. AjaxLoginProcessingFilter
2. JwtTokenAuthenticationProcessingFilter
3. AuthenticationManager
4. BCryptPasswordEncoder

Also, inside ```WebSecurityConfig#configure(HttpSecurity http)``` method we'll configure patterns to define protected/unprotected API endpoints. Please note that we have disabled CSRF protection because we are not using Cookies.

```language-java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    public static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";
    public static final String FORM_BASED_LOGIN_ENTRY_POINT = "/api/auth/login";
    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";
    public static final String TOKEN_REFRESH_ENTRY_POINT = "/api/auth/token";
    
    @Autowired private RestAuthenticationEntryPoint authenticationEntryPoint;
    @Autowired private AuthenticationSuccessHandler successHandler;
    @Autowired private AuthenticationFailureHandler failureHandler;
    @Autowired private AjaxAuthenticationProvider ajaxAuthenticationProvider;
    @Autowired private JwtAuthenticationProvider jwtAuthenticationProvider;
    
    @Autowired private TokenExtractor tokenExtractor;
    
    @Autowired private AuthenticationManager authenticationManager;
    
    @Autowired private ObjectMapper objectMapper;
        
    protected AjaxLoginProcessingFilter buildAjaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter filter = new AjaxLoginProcessingFilter(FORM_BASED_LOGIN_ENTRY_POINT, successHandler, failureHandler, objectMapper);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }
    
    protected JwtTokenAuthenticationProcessingFilter buildJwtTokenAuthenticationProcessingFilter() throws Exception {
        List<String> pathsToSkip = Arrays.asList(TOKEN_REFRESH_ENTRY_POINT, FORM_BASED_LOGIN_ENTRY_POINT);
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, TOKEN_BASED_AUTH_ENTRY_POINT);
        JwtTokenAuthenticationProcessingFilter filter 
            = new JwtTokenAuthenticationProcessingFilter(failureHandler, tokenExtractor, matcher);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(ajaxAuthenticationProvider);
        auth.authenticationProvider(jwtAuthenticationProvider);
    }
    
    @Bean
    protected BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        .csrf().disable() // We don't need CSRF for JWT based authentication
        .exceptionHandling()
        .authenticationEntryPoint(this.authenticationEntryPoint)
        
        .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        .and()
            .authorizeRequests()
                .antMatchers(FORM_BASED_LOGIN_ENTRY_POINT).permitAll() // Login end-point
                .antMatchers(TOKEN_REFRESH_ENTRY_POINT).permitAll() // Token refresh end-point
                .antMatchers("/console").permitAll() // H2 Console Dash-board - only for testing
        .and()
            .authorizeRequests()
                .antMatchers(TOKEN_BASED_AUTH_ENTRY_POINT).authenticated() // Protected API End-points
        .and()
            .addFilterBefore(buildAjaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(buildJwtTokenAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
```

#### PasswordEncoderConfig

BCrypt encoder that is in AjaxAuthenticationProvider.

```language-java
@Configuration
public class PasswordEncoderConfig {
    @Bean
    protected BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

#### BloomFilterTokenVerifier

This is dummy class. You should ideally implement your own TokenVerifier to check for revoked tokens.

```language-java
@Component
public class BloomFilterTokenVerifier implements TokenVerifier {
    @Override
    public boolean verify(String jti) {
        return true;
    }
}
```

### Conclusion

I heard people whispering on the web that loosing a JWT token is like loosing your house keys. So be careful.

## References

### [I don’t see the point in Revoking or Blacklisting JWT](https://www.dinochiesa.net/?p=1388)

### [Spring Security Architecture - Dave Syer](https://github.com/dsyer/spring-security-architecture)

### [Invalidating JWT](http://stackoverflow.com/questions/21978658/invalidating-json-web-tokens/36884683#36884683)

### [Secure and stateless JWT implementation](http://stackoverflow.com/questions/38557379/secure-and-stateless-jwt-implementation)

### [Learn JWT](https://github.com/dwyl/learn-json-web-tokens)

### [Opaque access tokens and cloud foundry](https://www.cloudfoundry.org/opaque-access-tokens-cloud-foundry/)

### [The unspoken vulnerability of JWTS](http://by.jtl.xyz/2016/06/the-unspoken-vulnerability-of-jwts.html)

### [How To Control User Identity Within Micro-services](http://nordicapis.com/how-to-control-user-identity-within-microservices/)

### [Why Does OAuth v2 Have Both Access and Refresh Tokens?](http://stackoverflow.com/questions/3487991/why-does-oauth-v2-have-both-access-and-refresh-tokens/12885823)

### [RFC-6749](https://tools.ietf.org/html/rfc6749)

### [Are breaches of JWT-based servers more damaging?](https://www.sslvpn.online/are-breaches-of-jwt-based-servers-more-damaging/)




