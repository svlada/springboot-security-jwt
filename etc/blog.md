## Table of contents:
1. <a title="Introduction: JWT Token" href="#introduction">Introduction</a>
2. <a title="Ajax authentication" id="ajax-authentication">Ajax authentication</a>

### <a name="introduction" id="introduction">Introduction</a>

Following are three scenarios that will be implemented in this tutorial:
1. Ajax Authentication
2. JWT Token
3. URL Based Authentication with JWT Token

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

Code for ajax authentication will reside in the following package: com/svlada/security/auth/ajax.

In order to implement Ajax Login in Spring Boot we'll need to implement a couple of components.

1. AjaxLoginProcessingFilter
2. AjaxAuthenticationProvider
3. AjaxAwareAuthenticationSuccessHandler
4. AjaxAwareAuthenticationFailureHandler
5. RestAuthenticationEntryPoint
6. WebSecurityConfig

Let's dive in the implementation details.

#### AjaxLoginProcessingFilter

#### Security Config

Create WebSecurityConfig class and put it in the com.svlada.security.config package.

WebSecurityConfig class needs to extend org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter.

#### Un-successufull access to protected resource

Request
```
GET /api/me HTTP/1.1
Host: localhost:9966
Cache-Control: no-cache
```

Response
```
{
  "timestamp": 1470301809962,
  "status": 401,
  "error": "Unauthorized",
  "message": "Full authentication is required to access this resource",
  "path": "/api/me"
}
```

#### Successufull ajax authentication