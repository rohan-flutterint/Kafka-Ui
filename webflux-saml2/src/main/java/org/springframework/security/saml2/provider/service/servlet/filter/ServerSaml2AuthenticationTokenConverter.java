package org.springframework.security.saml2.provider.service.servlet.filter;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static java.nio.charset.StandardCharsets.UTF_8;

public class ServerSaml2AuthenticationTokenConverter implements ServerAuthenticationConverter {

  private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
  private final ServerWebExchangeMatcher matcher;

  public ServerSaml2AuthenticationTokenConverter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
                                                 ServerWebExchangeMatcher matcher) {
    this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
    this.matcher = matcher;
  }

  @Override
  public Mono<Authentication> convert(ServerWebExchange exchange) {
    return matcher.matches(exchange)
        .map(mr -> mr.getVariables().get("registrationId").toString())
        .map(relyingPartyRegistrationRepository::findByRegistrationId)
        .map(rp -> createToken(exchange, rp));
  }

  private Saml2AuthenticationToken createToken(ServerWebExchange exchange, RelyingPartyRegistration rp) {
    String saml2Response = exchange.getRequest().getQueryParams().getFirst("SAMLResponse");
    byte[] b = Saml2Utils.decode(saml2Response);
    String responseXml = inflateIfRequired(exchange, b);
    String localSpEntityId = ServerSaml2Utils.getServiceProviderEntityId(rp, exchange.getRequest());

    return new Saml2AuthenticationToken(
        responseXml,
        exchange.getRequest().getURI().toString(),// TODO check this works as expected, was 'request.getRequestURL().toString()'
        rp.getRemoteIdpEntityId(),
        localSpEntityId,
        rp.getCredentials()
    );
  }

  private String inflateIfRequired(ServerWebExchange exchange, byte[] b) {
    if (HttpMethod.GET == exchange.getRequest().getMethod()) {
      return Saml2Utils.inflate(b);
    }
    else {
      return new String(b, UTF_8);
    }
  }
}
