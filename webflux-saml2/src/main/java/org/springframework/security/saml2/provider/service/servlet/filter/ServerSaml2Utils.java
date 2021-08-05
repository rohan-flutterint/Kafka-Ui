package org.springframework.security.saml2.provider.service.servlet.filter;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

public class ServerSaml2Utils {

  static String getServiceProviderEntityId(RelyingPartyRegistration rp, ServerHttpRequest request) {
    return Saml2Utils.resolveUrlTemplate(rp.getLocalEntityIdTemplate(), getApplicationUri(request), rp.getRemoteIdpEntityId(), rp.getRegistrationId());
  }

  static String getApplicationUri(ServerHttpRequest request) {
    // TODO check URL.toString equals to UrlUtils.buildFullRequestUrl(request)
    // TODO check request.getPath().contextPath().value() equals to request.getContextPath()
    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(request.getURI().toString())
        .replacePath(request.getPath().contextPath().value())
        .replaceQuery((String)null)
        .fragment((String)null)
        .build();
    return uriComponents.toUriString();
  }
}
