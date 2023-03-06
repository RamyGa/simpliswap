package com.ramy.simpliswap.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;


@Slf4j
@Controller
public class AppController {
    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/")//once logged in it will go to "/" (home page)
    public String homePage(){
        log.info("inside of home controller method");
        return "web_pages/index";
    }


    @GetMapping("/user/profile")//once logged in it will go to "/" (home page)
    public String userProfile(){

        log.info("User profile page requested");
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();

        if (authentication == null) {
            // User is not authenticated
            log.info("User is not authenticated");
        } else {
            // User is authenticated
            log.info("User is authenticated");
            log.info("User details: " + authentication.getDetails().toString());
        }
        return "web_pages/success";
    }
    @GetMapping("/fail")//once logged in it will go to "/" (home page)
    public String failure(){

        return "web_pages/success";
    }

    @GetMapping("/login")//once logged in it will go to "/" (home page)
    public String loginPage(){
        log.info("this is /login endpoint");
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();

        if (authentication == null) {
            // User is not authenticated
            log.info("User is not authenticated");
        } else {
            // User is authenticated
            log.info("User is authenticated");
            log.info("User details: " + authentication.getDetails().toString());
            log.info("User details continued: " + authentication.getName().toString());
            log.info("User details continued2: " + authentication.getCredentials().toString());
            log.info("User details continued3: " + authentication.getPrincipal().toString());
        }
        return "web_pages/login";
    }

    @GetMapping("/test")//once logged in it will go to "/" (home page)
    public String test(){
        log.info("User profile page requested");
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();

        if (authentication == null) {
            // User is not authenticated
            log.info("User is not authenticated");
        } else {
            // User is authenticated
            log.info("User is authenticated");
            log.info("User details: " + authentication.getDetails().toString());
        }
        return "web_pages/success";
    }




    //read that this might be required for the completion of full authentication? (This does not seem to ever be hit)
    @GetMapping("/login/oauth2/code/google")
    public String handleGoogleCallback(@RequestParam("code") String code,
                                       @RequestParam("state") String state,
                                       OAuth2AuthenticationToken authentication) {
        log.info("Inside handleGoogleCallback");
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());

        WebClient webClient = WebClient.builder()
                .baseUrl("https://oauth2.googleapis.com")
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .build();

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("grant_type", "authorization_code");
        requestBody.add("client_id", client.getClientRegistration().getClientId());
        requestBody.add("client_secret", client.getClientRegistration().getClientSecret());
        requestBody.add("redirect_uri", client.getClientRegistration().getRedirectUri());
        requestBody.add("code", code);

        OAuth2AccessTokenResponse accessTokenResponse = webClient.post()
                .uri("/token")
                .body(BodyInserters.fromFormData(requestBody))
                .retrieve()
                .bodyToMono(OAuth2AccessTokenResponse.class)
                .block();

        assert accessTokenResponse != null;
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                accessTokenResponse.getAccessToken().getTokenValue(),
                accessTokenResponse.getAccessToken().getIssuedAt(),
                accessTokenResponse.getAccessToken().getExpiresAt(),
                accessTokenResponse.getAccessToken().getScopes());

        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(accessTokenResponse.getRefreshToken().getTokenValue(), null);

        client = new OAuth2AuthorizedClient(
                client.getClientRegistration(),
                client.getPrincipalName(),
                accessToken,
                refreshToken);

        authorizedClientService.saveAuthorizedClient(client, authentication);

        return "redirect:/home";
    }
}

//    @GetMapping("/login/oauth2/authorization")//once logged in it will go to "/" (home page)
//    public String loginPage(){
//
//        return "web_pages/login";
//    }

//    @GetMapping("/login/oauth2/code/google")
//    public String googleLogin() {
//
//
//        return "success";
//    }



