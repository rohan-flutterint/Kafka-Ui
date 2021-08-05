package org.springframework.security.saml2.provider.service.servlet.filter;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

public class Saml2WebSsoAuthenticationWebFilter extends AuthenticationWebFilter {

  private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

  public Saml2WebSsoAuthenticationWebFilter(ReactiveAuthenticationManager authenticationManager,
                                            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
    super(authenticationManager);
    this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
  }
}
