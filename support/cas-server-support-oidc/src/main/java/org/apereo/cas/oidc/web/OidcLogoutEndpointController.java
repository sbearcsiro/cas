package org.apereo.cas.oidc.web;

import com.github.benmanes.caffeine.cache.LoadingCache;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.audit.AuditableContext;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.audit.AuditableExecutionResult;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.logout.SingleLogoutServiceLogoutUrlBuilder;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.profile.OAuth20ProfileScopeToAttributesFilter;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.web.endpoints.BaseOAuth20Controller;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.util.EncodingUtils;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Optional;

/**
 * This is {@link OidcLogoutEndpointController}.
 *
 * @author Misagh Moayyed
 * @since 5.3.5
 */
@Slf4j
public class OidcLogoutEndpointController extends BaseOAuth20Controller {
    private final AuditableExecution registeredServiceAccessStrategyEnforcer;
    private final SingleLogoutServiceLogoutUrlBuilder singleLogoutServiceLogoutUrlBuilder;
    private final LoadingCache<String, Optional<RsaJsonWebKey>> defaultJsonWebKeystoreCache;

    public OidcLogoutEndpointController(final ServicesManager servicesManager, final TicketRegistry ticketRegistry,
                                        final AccessTokenFactory accessTokenFactory,
                                        final PrincipalFactory principalFactory,
                                        final ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory,
                                        final OAuth20ProfileScopeToAttributesFilter scopeToAttributesFilter,
                                        final CasConfigurationProperties casProperties,
                                        final CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator,
                                        final AuditableExecution registeredServiceAccessStrategyEnforcer,
                                        final SingleLogoutServiceLogoutUrlBuilder singleLogoutServiceLogoutUrlBuilder,
                                        final LoadingCache<String, Optional<RsaJsonWebKey>> defaultJsonWebKeystoreCache) {
        super(servicesManager, ticketRegistry, accessTokenFactory, principalFactory, webApplicationServiceServiceFactory,
                scopeToAttributesFilter, casProperties, ticketGrantingTicketCookieGenerator);
        this.registeredServiceAccessStrategyEnforcer = registeredServiceAccessStrategyEnforcer;
        this.singleLogoutServiceLogoutUrlBuilder = singleLogoutServiceLogoutUrlBuilder;
        this.defaultJsonWebKeystoreCache = defaultJsonWebKeystoreCache;
    }

    /**
     * Handle request.
     *
     * @param postLogoutRedirectUrl the post logout redirect url
     * @param state                 the state
     * @param idToken               the id token
     * @param request               the request
     * @param response              the response
     * @return the response entity
     */
    @GetMapping(value = '/' + OidcConstants.BASE_OIDC_URL + '/' + OidcConstants.LOGOUT_URL, produces = MediaType.APPLICATION_JSON_VALUE)
    @SneakyThrows
    public View handleRequestInternal(@RequestParam(value = "post_logout_redirect_uri", required = false) final String postLogoutRedirectUrl,
                                      @RequestParam(value = "state", required = false) final String state,
                                      @RequestParam(value = "id_token_hint", required = false) final String idToken,
                                      final HttpServletRequest request, final HttpServletResponse response) {

        if (StringUtils.isNotBlank(idToken)) {
            final JwtClaims claims = validateToken(idToken);

            final String clientId = claims.getStringClaimValue(OAuth20Constants.CLIENT_ID);

            final OAuthRegisteredService registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(this.servicesManager, clientId);
            final WebApplicationService service = webApplicationServiceServiceFactory.createService(clientId);

            final AuditableContext audit = AuditableContext.builder()
                    .service(service)
                    .registeredService(registeredService)
                    .retrievePrincipalAttributesFromReleasePolicy(Boolean.FALSE)
                    .build();
            final AuditableExecutionResult accessResult = this.registeredServiceAccessStrategyEnforcer.execute(audit);
            accessResult.throwExceptionIfNeeded();

            final Collection<URL> urls = singleLogoutServiceLogoutUrlBuilder.determineLogoutUrl(registeredService, service);
            if (StringUtils.isNotBlank(postLogoutRedirectUrl)) {
                final boolean matchResult = urls.stream().anyMatch(url -> url.toString().equalsIgnoreCase(postLogoutRedirectUrl));
                if (matchResult) {
                    return getLogoutRedirectView(state, postLogoutRedirectUrl);
                }
            }

            if (urls.isEmpty()) {
                return getLogoutRedirectView(state, null);
            }
            return getLogoutRedirectView(state, urls.toArray()[0].toString());
        }

        return getLogoutRedirectView(state, null);
    }

    private View getLogoutRedirectView(final String state, final String redirectUrl) {
        final UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(casProperties.getServer().getLogoutUrl());
        if (StringUtils.isNotBlank(redirectUrl)) {
            builder.queryParam(casProperties.getLogout().getRedirectParameter(), redirectUrl);
        }
        if (StringUtils.isNotBlank(state)) {
            builder.queryParam(OAuth20Constants.STATE, redirectUrl);
        }
        final String logoutUrl = builder.build().toUriString();
        return new RedirectView(logoutUrl);
    }

    @SneakyThrows
    private JwtClaims validateToken(final String token) {
        final PublicJsonWebKey jsonWebKey = getSigningKey();
        if (jsonWebKey.getPublicKey() == null) {
            throw new IllegalArgumentException("JSON web key used to validate the id token signature has no associated public key");
        }
        final byte[] jwt = EncodingUtils.verifyJwsSignature(jsonWebKey.getPublicKey(), token);
        if (jwt == null) {
            throw new IllegalArgumentException("JWS Signature is invalid");
        }
        final String result = new String(jwt, StandardCharsets.UTF_8);
        final JwtClaims claims = JwtClaims.parse(result);

        LOGGER.debug("Validated claims as [{}]", claims);
        if (StringUtils.isBlank(claims.getIssuer())) {
            throw new IllegalArgumentException("Claims do not container an issuer");
        }

        if (claims.getIssuer().equalsIgnoreCase(getIssuer())) {
            throw new IllegalArgumentException("Issuer assigned to claims does not match " + getIssuer());
        }

        if (StringUtils.isBlank(claims.getStringClaimValue(OAuth20Constants.CLIENT_ID))) {
            throw new IllegalArgumentException("Claims do not contain a client id claim");
        }
        return claims;
    }

    private PublicJsonWebKey getSigningKey() {
        final Optional<RsaJsonWebKey> jwks = defaultJsonWebKeystoreCache.get(getIssuer());
        if (!jwks.isPresent()) {
            throw new IllegalArgumentException("No signing key could be found for issuer " + getIssuer());
        }
        return jwks.get();
    }

    private String getIssuer() {
        return casProperties.getAuthn().getOidc().getIssuer();
    }
}
