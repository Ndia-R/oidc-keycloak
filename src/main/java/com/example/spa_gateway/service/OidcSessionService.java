package com.example.spa_gateway.service;

import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpSession;

@Service
public class OidcSessionService {
    private static final String STATE_ATTRIBUTE = "oidc_state";
    private static final String NONCE_ATTRIBUTE = "oidc_nonce";
    private static final String CODE_VERIFIER_ATTRIBUTE = "oidc_code_verifier";

    // state関連

    public void storeState(HttpSession session, String state) {
        session.setAttribute(STATE_ATTRIBUTE, state);
    }

    public String getAndRemoveState(HttpSession session) {
        String state = (String) session.getAttribute(STATE_ATTRIBUTE);
        session.removeAttribute(STATE_ATTRIBUTE);
        return state;
    }

    public boolean validateState(HttpSession session, String receivedState) {
        String storedState = getAndRemoveState(session);
        return storedState != null && storedState.equals(receivedState);
    }

    // nonce関連

    public void storeNonce(HttpSession session, String nonce) {
        session.setAttribute(NONCE_ATTRIBUTE, nonce);
    }

    public String getNonce(HttpSession session) {
        return (String) session.getAttribute(NONCE_ATTRIBUTE);
    }

    // PKCE Code Verifier関連

    public void storeCodeVerifier(HttpSession session, String codeVerifier) {
        session.setAttribute(CODE_VERIFIER_ATTRIBUTE, codeVerifier);
    }

    public String getAndRemoveCodeVerifier(HttpSession session) {
        String codeVerifier = (String) session.getAttribute(CODE_VERIFIER_ATTRIBUTE);
        session.removeAttribute(CODE_VERIFIER_ATTRIBUTE);
        return codeVerifier;
    }
}