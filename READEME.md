# Oauth Demo

Oauth2 的文档太多了，而且 Spring 也出了个新产品 `spring-authorization-server` ，没整明白，所以自己 debug 整理这个 Oauth2 认证的过程。

### Oauth2 客户端跳转过程

### 零、客户端获取密钥

1. 客户端启动会经过 `OAuth2ClientPropertiesRegistrationAdapter` 类的 `getClientRegistrations` 方法向授权服务器获取客户顿配置信息，访问授权服务器的 `/.well-known/openid-configuration`
2. 授权服务器接收到请求后，进入 `OidcProviderConfigurationEndpointFilter` 过滤链，端点为 `/.well-known/openid-configuration` ，返回公钥信息给客户端


### 一、认证页面获取过程

#### 客户端

1. 登陆无权限拦截，被 `AbstractSecurityInterceptor` 拦截器拦截，报 `AccessDeniedException` 异常
2. 通过 `handleAccessDeniedException` 异常捕获，跳转到到 `LoginUrlAuthenticationEntryPoint ` 中 `commence()` 方法处理，跳转到登陆页面。
3. `redirect` 跳转到设置的登陆页(demo中为 `/oauth2/authorization/auth-oidc` )。
4. 关键过滤器`OAuth2AuthorizationRequestRedirectFilter` 拦截，进入 `doFilterInternal()` 方法后会转到 `DefaultOAuth2AuthorizationRequestResolver` 类中的 `resolve` 方法处理，该方法有很多重载方法
   - 进入 `resolve` 方法，匹配 `/oauth2/authorization/**` 获得 `registrationId` (demo中为 `auth-oidc`)
   - 进入另一个 `resolve` 重载方法，通过 `registrationId` 从内存中获取注册了的客户端信息 `Client Registration`，即配置文件注入的 `Oauth Client` 信息
   - `expandRedirectUri` 方法，会构造 `redirectUri` 得到 `http://auth-server:8080/login/oauth2/code/auth-oidc` ，授权服务器认证通过后则会跳回该地址
   - 最后会得到 `OAuth2AuthorizationRequest` 这包含了客户端的信息和将要跳转的地址，通过 `sendRedirectForAuthorization` 跳转到认证服务器。（最终构造的url为 `http://auth-server:9000/oauth2/authorize?response_type=code&client_id=auth&scope=openid&state=xxx&redirect_uri=http://auth-server:8080/login/oauth2/code/auth-oidc&nonce=xxx` ）

#### 授权服务器

1. 接收到客户端的认证请求，进入 `OAuth2AuthorizationEndpointFilter` 过滤器（拦截 `/login/oauth2/**` 端点）
2. 然后进入 `OAuth2AuthorizationCodeRequestAuthenticationProvider` 认证提供商的 `authenticateAuthorizationRequest` 方法进行鉴权，报 `AccessDeniedException` 异常
   - 这里会校验在注册进授权服务器的 `Client Registration` 中支不支持客户端传过来的 `redirectUri` 、 `scope`
3. 通过 `handleAccessDeniedException` 异常捕获，跳转到到 `LoginUrlAuthenticationEntryPoint` 中 `commence()` 方法处理，跳转到登陆页面。
6. `redirect` 跳转到设置的登陆页(demo中为 `/login` )。
7. 然后经过一系列过滤链，最终在 `DefaultLoginPageGeneratingFilter` 过滤连返回登录页给用户

***

### 二、登陆过程

#### 授权服务器

1. 在登陆页面输入用户名和密码
2. 首先会认证用户名和密码，进入关键过滤连 `AbstractAuthenticationProcessingFilter` ==> `UsernamePasswordAuthenticationFilter` ，（拦截`/login` 端点）
   - 会进入关键的 `UserDetailsService` 具体的实现类中（demo 使用了 `InMemoryUserDetailsManager` ），获取用户信息 `UserDetails`
3. 登陆认证成功后，会在 `SavedRequestAwareAuthenticationSuccessHandler` 类中的 `onAuthenticationSuccess` 方法做跳转处理，从session的获取第一次访问授权服务器的 url 作跳转( `http://auth-server:9000/oauth2/authorize?response_type=code&client_id=auth&scope=openid&state=xxx&redirect_uri=http://auth-server:8080/login/oauth2/code/auth-oidc&nonce=xxx` )
4. 重新进入授权服务器，将会认证客户端信息，经过 `OAuth2AuthorizationEndpointFilter` 过滤器
5. 然后进入 `OAuth2AuthorizationCodeRequestAuthenticationProvider` 认证提供商的 `authenticateAuthorizationRequest` 方法进行鉴权
   - 这次鉴权通过后会调用 `generateAuthorizationCode()` 方法生成 code
   - 构建 `OAuth2Authorization` 保存到数据库，用来下次一访问授权服务器带上code做校验使用
6. 最后会进入 `sendAuthorizationResponse` 方法中，携带 `code` 数据返回给客户端，（url 为 `http://auth-server:8080/login/oauth2/code/auth-oidc?code=xxx` ）

#### 客户端

1. 接收到授权服务器传回来的 `code` ，将会被 `OAuth2LoginAuthenticationFilter` 过滤链拦截（拦截端点：`/login/oauth2/code/*` ），进入 `attemptAuthentication` 方法
   - 从 `request` 获取 `code` 的值
   - 获取 `authorizationRequest` ，不清楚为何如果客户端改成使用域名访问回一直取出来的值为null 
2. 进入 `OidcAuthorizationCodeAuthenticationProvider` 的 `authenticate` 认证提供商的进行鉴权
   - 调用封装好的 `getResponse` 方法，获取 `token (jwt)` ，携带 `code` 访问 `/oauth2/token` 端点，请求成功将会获得 `accessToken` 和 `refreshToken`
   

#### 授权服务器

1. 接收客户端传回来的 `code`，将会被 `OAuth2ClientAuthenticationFilter` 过滤链拦截（拦截端点：`/oauth2/token` ），对客户端信息进行鉴权
   - 认证提供商为 `OAuth2ClientAuthenticationProvider` ，主要是校验储存在认证服务器中的客户端信息中的账号密码是否正确
2. 接下来会进入 `OAuth2TokenEndpointFilter` 过滤器，先对请求进行分析 `grantTypes` 是什么类型的认证方式
   - 判断为 `authorization_code` 认证方式将会进入 `OAuth2AuthorizationCodeAuthenticationProvider` 类中进行认证，
     1. 通过 `authorization_code` 从数据库查找下发的 `authorization_code`
     2. 获取到对应的认证信息后，会对 `authorization_code` 判断是否有效
     3. 验证成功后将会生成对应的 token ，如果为 `authorization_code` 认证方式将会生成 `refreshToken`， `oidc` 的认证方式还会在其基础上增强 user 的用户信息
     4. 一顿生成 `token` 的操作后将会把认证好的信息保存到数据库中
     5. 最后使用 jwt 的形式返回给客户端 token

#### 客户端

1. 回到客户端的 `OidcAuthorizationCodeAuthenticationProvider` 
   - 客户端顺利获取到 `token` 后，` 将会解析 `token (jwt)` 的内容，生成 `OidcUser`，最终保存到 `authenticationResult` 中
2. 获取到用户信息 `authenticationResult` 后，回到 `OAuth2LoginAuthenticationFilter` 过滤链中， 对认证信息加工后将会保存到认证信息的储存库中，demo中使用默认的方式，将会进入 `InMemoryOAuth2AuthorizedClientService` 类中（**改造点**）
3. 最后更新 session 后跳转到最先访问的页面

***

**以上认证完成**

### 其他

1. `state` 生成位置 `DefaultOAuth2AuthorizationRequestResolver` 中的 `resolve` 方法
2. 客户端请求授权服务器的时候会在请求头中的 `Authorization` 携带客户端信息，使用base64加密，如 `Basic YXV0aDoxMjM0NTY=`