package com.example.spa_gateway.service;

import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpSession;

@Service
public class OidcSessionService {
    
    private static final String STATE_ATTRIBUTE = "oidc_state";
    private static final String NONCE_ATTRIBUTE = "oidc_nonce";
    
    public void storeState(HttpSession session, String state) {
        session.setAttribute(STATE_ATTRIBUTE, state);
    }
    
    public void storeNonce(HttpSession session, String nonce) {
        session.setAttribute(NONCE_ATTRIBUTE, nonce);
    }
    
    public String getAndRemoveState(HttpSession session) {
        String state = (String) session.getAttribute(STATE_ATTRIBUTE);
        session.removeAttribute(STATE_ATTRIBUTE);
        return state;
    }
    
    public String getAndRemoveNonce(HttpSession session) {
        String nonce = (String) session.getAttribute(NONCE_ATTRIBUTE);
        session.removeAttribute(NONCE_ATTRIBUTE);
        return nonce;
    }
    
    public boolean validateState(HttpSession session, String receivedState) {
        String storedState = getAndRemoveState(session);
        return storedState != null && storedState.equals(receivedState);
    }
    
    public String getNonce(HttpSession session) {
        return (String) session.getAttribute(NONCE_ATTRIBUTE);
    }
}