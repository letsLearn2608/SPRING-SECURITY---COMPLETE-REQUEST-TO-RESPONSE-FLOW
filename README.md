# SPRING-SECURITY---COMPLETE-REQUEST-TO-RESPONSE-FLOW
====================================================
1. OVERVIEW
------------
Spring Security works like a series of intelligent gates (filters) that examine each request before it
reaches your REST API.
It ensures only authenticated and authorized users can access protected endpoints.
Request -> Filters -> Authentication -> Authorization -> Controller -> Response

====================================================
2. FILTER CHAIN STAGES
-----------------------
1. CORS FILTER
---------------
Purpose: Handles cross-origin requests (CORS).
- Checks the 'Origin' header.
- If allowed, adds Access-Control-Allow-* headers.
- Handles preflight OPTIONS requests.
- Does not perform authentication.
2. CSRF FILTER
----------------
Purpose: Protects against Cross-Site Request Forgery.
- Ensures modifying requests (POST, PUT, DELETE) contain a valid CSRF token.
- Not required for stateless JWT-based APIs (usually disabled).
3. USERNAMEPASSWORDAUTHENTICATIONFILTER
----------------------------------------
Purpose: Handles form or JSON-based login.
- Intercepts /login requests.
- Reads username & password.
- Creates UsernamePasswordAuthenticationToken.
- Delegates to AuthenticationManager.
- On success: saves Authentication in SecurityContextHolder.
4. CUSTOM JWT AUTHENTICATION FILTER (OncePerRequestFilter)
------------------------------------------------------------
Purpose: Authenticates every request using JWT token.
- Runs once per request.
- Checks Authorization header for Bearer token.
- Validates token (signature, expiry, subject).
- Loads user from DB (UserDetailsService).
- Creates Authentication and saves it in SecurityContextHolder.
- If invalid: forwards to ExceptionTranslationFilter.
5. ANONYMOUSAUTHENTICATIONFILTER
---------------------------------
Purpose: Ensures a request always has an identity.
- If no Authentication exists, creates an AnonymousAuthenticationToken.
- Used for public endpoints with permitAll().
6. EXCEPTIONTRANSLATIONFILTER
-------------------------------
Purpose: Catches exceptions from deeper filters.
- AuthenticationException -> 401 Unauthorized.
- AccessDeniedException -> 403 Forbidden.
- Uses AuthenticationEntryPoint and AccessDeniedHandler for responses.
7. FILTERSECURITYINTERCEPTOR
------------------------------
Purpose: Final gatekeeper for authorization.
- Checks roles/authorities against configured access rules.
- If access granted -> controller executes.
- If denied -> AccessDeniedException raised.
====================================================


3. AFTER FILTERS
-----------------
Once all filters approve the request:
1. SecurityContextHolder contains the Authentication object.
- Created by JWT or login filters.
- Stores username, roles, and authorities.
2. DispatcherServlet forwards the request to the appropriate controller.
3. Inside controller:
- Access current user via Principal, Authentication, or @AuthenticationPrincipal.
4. Business logic executes for the authenticated user.
5. Method-level security checks (if used):
- @PreAuthorize("hasRole('ADMIN')")
- @Secured("ROLE_USER")
6. Response passes back through the filter chain (reverse order):
- Cleans up SecurityContextHolder.
- Adds CORS headers or handles errors if needed.
====================================================
4. SUMMARY TABLE
-----------------
| Step | Component | Role |
|------|------------|------|
| 1 | CorsFilter | Handles cross-origin requests |
| 2 | CsrfFilter | Validates CSRF tokens (if enabled) |
| 3 | UsernamePasswordAuthenticationFilter | Handles form-based login |
| 4 | JWT Filter (custom) | Authenticates requests via token |
| 5 | AnonymousAuthenticationFilter | Creates anonymous user if unauthenticated |
| 6 | ExceptionTranslationFilter | Converts exceptions into 401/403 responses |
| 7 | FilterSecurityInterceptor | Performs authorization checks |
| 8 | SecurityContextHolder | Stores authenticated user info |
| 9 | Controller | Executes only if authorized |
====================================================
5. COMPLETE FLOW (SIMPLIFIED VIEW)
-----------------------------------
Client Request
|
v
Spring Security Filter Chain
|
v
Authentication (JWT / Login)
|
v
Authorization (Roles / Rules)
|
v
Controller executes with authenticated Principal
|
v
Response flows back through filters
|
v
SecurityContextHolder cleared
====================================================
6. KEY TAKEAWAYS
----------------
- Filters run before controllers.
- Authentication identifies the user.
- Authorization verifies permissions.
- SecurityContextHolder stores user info per request.
- Stateless JWT APIs disable CSRF.
- ExceptionTranslationFilter ensures clean 401/403 responses.
- Once filters pass, controller executes normally.
====================================================
