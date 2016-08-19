## Table of contents:
1. <a title="Introduction: JWT Token" href="#introduction">Introduction</a>
2. <a title="Ajax authentication" id="ajax-authentication">Ajax authentication</a>

### <a name="introduction" id="introduction">Introduction</a>

Following are three scenarios that will be implemented in this tutorial:
1. Ajax Authentication
2. JWT Token Authentication

### Prerequisites

First step is to create empty Spring Boot project. Visit spring initializr website(https://start.spring.io/) to generate boilerplate.

Lets start by creating base package structure for our sample code. 

```
+---main
|   +---java
|   |   +---com
|   |   |   \---svlada
|   |   |       +---common
|   |   |       \---security
|   |   |           +---auth
|   |   |           |   +---ajax
|   |   |           |   \---jwt
|   |   |           +---config
|   |   |           +---exceptions
|   |   |           \---model
|   \---resources
|       +---static
|       \---templates
\---test
    \---java
        \---com
            \---svlada
```

### <a name="ajax-authentication" id="ajax-authentication">Ajax authentication</a>

In order to implement Ajax Login in Spring Boot we'll need to implement a couple of components:

1. AjaxLoginProcessingFilter
2. AjaxAuthenticationProvider
3. AjaxAwareAuthenticationSuccessHandler
4. AjaxAwareAuthenticationFailureHandler
5. RestAuthenticationEntryPoint
6. WebSecurityConfig

Authentication flow starts with AJAX authentication request as shown below:

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

User credentials are sent in JSON Payload of authentication request. If credentials are valid, authentication API will respond with HTTP status "200 OK". Additionaly JWT token is included in the HTTP response body. JWT token is then used to make authenticated API requests.

Sample HTTP Authentication reponse with JWT Token included:
```
{
    "token": "eyJhbGciOiJIUzUxMiJ9.eyJyb2xlcyI6WyJST0xFX0FETUlOIl0sImlhdCI6MTQ3MDM4NDg4NSwiZXhwIjoxNDcwMzg1MDA1fQ.pvAyzZDd8F8snjH1a-geHGXFAnN-vnMJ5uW9TmF7nFvIGaYYUh-B5kyAr4nYioB07fwXFw6s22zPc3Ge1bekfQ"
}
```

JWT Token consists of three parts: Header, Claims and Signature. Decoded values are presented below:

Header
```

{
    "alg": "HS512"
}
```
Claims
```

{
	iss: "http://svlada.com",
	sub: "svlada@gmail.com",
	"roles": [
        "ROLE_ADMIN"
    ],
  	"iat": 1470384885, 
    "exp": 1470385005
}
```
Signature (encoded)
```
pvAyzZDd8F8snjH1a-geHGXFAnN-vnMJ5uW9TmF7nFvIGaYYUh-B5kyAr4nYioB07fwXFw6s22zPc3Ge1bekfQ
```

Let's dive in the implementation details.

#### AjaxLoginProcessingFilter

AbstractAuthenticationProcessingFilter class is responsible for processing of HTTP-based authentication requests. Please note that AuthenticationManager must be set for this class.

AjaxLoginProcessingFilter is overriding AbstractAuthenticationProcessingFilter to provide implementation for AJAX based authentication. 

Parsing and basic validation of incoming JSON payload is done in the AjaxLoginProcessingFilter#attemptAuthentication method. If authentication JSON payload is valid, actual authentication logic is delegated to AjaxAuthenticationProvider class.

In case of successuful authentication AjaxLoginProcessingFilter#successfulAuthentication is called.
In case of application failure AjaxLoginProcessingFilter#unsuccessfulAuthentication is called.

```language-java
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private static Logger logger = LoggerFactory.getLogger(AjaxLoginProcessingFilter.class);

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    private final ObjectMapper objectMapper;
    
    public AjaxLoginProcessingFilter(String defaultFilterProcessesUrl, 
            AuthenticationSuccessHandler successHandler, 
            AuthenticationFailureHandler failureHandler, 
            ObjectMapper mapper) {
        super(defaultFilterProcessesUrl);
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.objectMapper = mapper;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
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

AjaxAuthenticationProvider class responsiblity is to:

1. Verify user credentials against database, ldap or some other system which holds user data.
2. Throw authentication exception in case of that username and password doesn't match record in the database, username doesnt exists, etc.
3. Create UserContext and populate it with information you need.
4. Create JWT Token and sign it with the private key (JwtTokenFactory).

```language-java
@Component
public class AjaxAuthenticationProvider implements AuthenticationProvider {
    private final JwtTokenFactory tokenFactory;
    private final UserService userService;
    
    @Autowired
    public AjaxAuthenticationProvider(final JwtTokenFactory tokenFactory, final UserService userService) {
        this.tokenFactory = tokenFactory;
        this.userService = userService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.notNull(authentication, "No authentication data provided.");

        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        UserContext userContext = userService.loadUser(username, password);

        SafeJwtToken safeJwtToken = tokenFactory.createSafeToken(userContext, userContext.getAuthorities());

        return new JwtAuthenticationToken(userContext, safeJwtToken, userContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
```

Let's focus for a moment on how JWT token is created. In this tutorial we are using [Java JWT](https://github.com/jwtk/jjwt) library created by [Stormpath](https://stormpath.com/).

Make sure that this JJWT dependency is included in your pom.xml.

```language-xml
<dependency>
	<groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>${jjwt.version}</version>
</dependency>
```

JwtTokenFactory#createSafeToken method will create signed Jwt Token.

Please note that if you are instantiating Claims object outside of Jwts.builder() make sure to first invoke Jwts.builder()#setClaims(claims). Why? Well, if you don't do that, Jwts.builder will, by default, create empty Claims object. What that means? Well if you call Jwts.builder()#setClaims() after you have set subject with Jwts.builder()#setSubject() your subject will be lost. Simply new instance of Claims class will overwrite default one created by Jwts.builder().

```
@Component
public class JwtTokenFactory {
    @Autowired
    private JwtSettings settings;

    /**
     * Factory method for issuing new JWT Tokens.
     * 
     * @param username
     * @param roles
     * @return
     */
    public SafeJwtToken createSafeToken(UserContext userContext, final Collection<GrantedAuthority> roles) {
        if (StringUtils.isBlank(userContext.getUsername())) {
            throw new IllegalArgumentException("Cannot create JWT Token without username");
        }

        if (Collections.isEmpty(roles)) {
            throw new IllegalArgumentException("Cannot create JWT Token without roles");
        }

        DateTime currentTime = new DateTime();

        Claims claims = Jwts.claims();
        claims.put("roles", AuthorityUtils.authorityListToSet(roles));

        String token = Jwts.builder()
          .setClaims(claims)
          .setIssuer(settings.getTokenIssuer())
          .setSubject(userContext.getUsername())
          .setIssuedAt(currentTime.toDate())
          .setExpiration(currentTime.plusMinutes(settings.getTokenExpirationTime()).toDate())
          .signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
        .compact();

        return new SafeJwtToken(token, claims);
    }

    /**
     * Unsafe version of JWT token is created.
     * 
     * <strong>WARNING:</strong> Token signature validation is not performed.
     * 
     * @param tokenPayload
     * @return unsafe version of JWT token.
     */
    public UnsafeJwtToken createUnsafeToken(String tokenPayload) {
        return new UnsafeJwtToken(tokenPayload);
    }
}
```

We have extended AbstractAuthenticationToken and implemented JwtAuthenticationToken that will be passed through application as an authentication object.

```
public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 2877954820905567501L;

    private JwtToken safeToken;
    private UnsafeJwtToken unsafeToken;

    private UserContext userContext;

    public JwtAuthenticationToken(UnsafeJwtToken unsafeToken) {
        super(null);
        this.unsafeToken = unsafeToken;
        this.setAuthenticated(false);
    }

    public JwtAuthenticationToken(UserContext userContext, SafeJwtToken token,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.safeToken = token;
        this.userContext = userContext;
        super.setAuthenticated(true);
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }
        super.setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.userContext;
    }

    public JwtToken getSafeToken() {
        return this.safeToken;
    }

    public UnsafeJwtToken getUnsafeToken() {
        return unsafeToken;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }
}
```

#### AjaxAwareAuthenticationSuccessHandler

AjaxAwareAuthenticationSuccessHandler is simple class and it's used by Spring to actually send HTTP response upon successuful authentication.


```
@Component
public class AjaxAwareAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final ObjectMapper mapper;

    @Autowired
    public AjaxAwareAuthenticationSuccessHandler(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        JwtToken token = ((JwtAuthenticationToken) authentication).getSafeToken();

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        mapper.writeValue(response.getWriter(), token);

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

#### AjaxAwareAuthenticationFailureHandler

AjaxAwareAuthenticationFailureHandler is invoked by Spring in case of authentication failure. You can create specific error message based on exception type that have occured during the authentication process.

```
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

#### WebSecurityConfig - Initial version to support AJAX based login

This is first version of WebSecurityConfig. We will add more configuration to it once we start with showcase of JWT Authentication flow.

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    public static final String FORM_BASED_LOGIN_ENTRY_POINT = "/api/auth/login";
    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";

    @Autowired private RestAuthenticationEntryPoint authenticationEntryPoint;
    @Autowired private AuthenticationSuccessHandler successHandler;
    @Autowired private AuthenticationFailureHandler failureHandler;
    @Autowired private AjaxAuthenticationProvider ajaxAuthenticationProvider;

    @Autowired private AuthenticationManager authenticationManager;
    
    @Autowired private ObjectMapper objectMapper;
    
    @Bean
    protected AjaxLoginProcessingFilter buildAjaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter filter = new AjaxLoginProcessingFilter(FORM_BASED_LOGIN_ENTRY_POINT, successHandler, failureHandler, objectMapper);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(ajaxAuthenticationProvider);
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
        .and()
            .addFilterBefore(buildAjaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
```


### <a name="jwt-token-authentication" id="jwt-token-authentication">Jwt token authentication</a>




## References

### [Spring Security Architecture - Dave Syer](https://github.com/dsyer/spring-security-architecture)

### [](http://stackoverflow.com/questions/21978658/invalidating-json-web-tokens/36884683#36884683)

### [](http://stackoverflow.com/questions/38557379/secure-and-stateless-jwt-implementation)

http://by.jtl.xyz/2016/06/the-unspoken-vulnerability-of-jwts.html

http://nordicapis.com/how-to-control-user-identity-within-microservices/

http://stackoverflow.com/questions/3487991/why-does-oauth-v2-have-both-access-and-refresh-tokens/12885823

https://tools.ietf.org/html/rfc6749#section-1.4

Keep user identity in the JWT but not user roles.

Loosing a JWT token is like loosing your house keys. 

https://www.dinochiesa.net/?p=1388

http://by.jtl.xyz/2016/06/the-unspoken-vulnerability-of-jwts.html

true statelessness and revocation are mutually exclusive


https://www.sslvpn.online/are-breaches-of-jwt-based-servers-more-damaging/

http://nordicapis.com/how-to-control-user-identity-within-microservices/

https://tools.ietf.org/html/rfc6749