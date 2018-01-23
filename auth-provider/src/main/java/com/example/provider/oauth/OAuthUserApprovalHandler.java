package com.example.provider.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class OAuthUserApprovalHandler extends ApprovalStoreUserApprovalHandler {

    private ClientDetailsService clientDetailsService;

    private ApprovalStore approvalStore;

    private boolean useApprovalStore = true;

    @Autowired
    public OAuthUserApprovalHandler(ClientDetailsService clientDetailsService, ApprovalStore approvalStore) {
        this.clientDetailsService = clientDetailsService;
        this.approvalStore = approvalStore;
        this.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
        this.setApprovalStore(approvalStore);
        this.setClientDetailsService(clientDetailsService);
    }

    @Override
    public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        boolean approved = true;
        if (useApprovalStore) {
            authorizationRequest = super.checkForPreApproval(authorizationRequest, userAuthentication);
            approved = authorizationRequest.isApproved();
        } else {
            if (clientDetailsService != null) {
                Set<String> requestScope = authorizationRequest.getScope();
                ClientDetails clientDetails = clientDetailsService.loadClientByClientId(authorizationRequest.getClientId());
                for (String scope : requestScope) {
                    if (clientDetails.isAutoApprove(scope)) {
                        approved = true;
                        break;
                    }
                }
            }
        }
        authorizationRequest.setApproved(approved);
        return authorizationRequest;
    }
}
