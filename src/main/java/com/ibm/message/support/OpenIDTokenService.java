package com.ibm.message.support;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * This class is used to extract Authentication from IBM ID token
 * 
 * @author Jackie King (szwbwang@cn.ibm.com)
 * @date Sep 28, 2016 2:46:47 AM
 * @version 1.0.0
 * @since 1.0.0
 * */
public class OpenIDTokenService implements ResourceServerTokenServices {

	protected final Log logger = LogFactory.getLog(getClass());

	private OAuth2RestOperations restTemplate;
	private final String ID_TOKEN = "id_token";
	private final String USER_NAME = "sub";
	private final String BLUE_GROUPS = "blueGroups";

	public OpenIDTokenService(OAuth2RestOperations restTemplate) {
		Assert.notNull(restTemplate, "template must not be null");
		this.restTemplate = restTemplate;
	}

	@Override
	public OAuth2Authentication loadAuthentication(String accessToken)
			throws AuthenticationException, InvalidTokenException {

		Map<String, Object> map = retrieveIDToken(accessToken);
		if (map.containsKey("error")) {
			this.logger.debug("Retrieve ID token error: " + map.get("error"));
			throw new InvalidTokenException(accessToken);
		}

		return extractAuthentication(map);
	}

	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException(
				"Not supported: read access token");
	}

	protected boolean validateIDToken(String signature) {
		// TODO Please implement you owner business in sub class
		return true;
	}

	private Map<String, Object> retrieveIDToken(String accessToken) {
		try {
			OAuth2RestOperations restTemplate = this.restTemplate;

			OAuth2AccessToken existingToken = restTemplate
					.getOAuth2ClientContext().getAccessToken();
			if (existingToken == null
					|| !accessToken.equals(existingToken.getValue())) {
				throw new InvalidTokenException("Access token not match: "
						+ accessToken);
			}

			Map<String, Object> map = existingToken.getAdditionalInformation();
			if (null == map || map.isEmpty() || !map.containsKey(ID_TOKEN)) {
				throw new InvalidTokenException("No ID token available: "
						+ accessToken);
			}

			return decodeIDToken((String) map.get(ID_TOKEN));
		} catch (Exception ex) {
			this.logger.info("Could not retrieve ID token: " + ex.getClass()
					+ ", " + ex.getMessage());
			return Collections.<String, Object> singletonMap("error",
					"Could not retrieve ID token");
		}
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> decodeIDToken(String idToken) {

		Map<String, Object> resultMap = new HashMap<String, Object>();

		try {
			String idTokenArr[] = idToken.split("\\.");
			Base64.Decoder decoder = Base64.getDecoder();
			ObjectMapper mapper = new ObjectMapper();

			String alg = new String(decoder.decode(idTokenArr[0]), "UTF-8");
			String jwt = new String(decoder.decode(idTokenArr[1]), "UTF-8");
			String signature = idTokenArr[2];

			if (validateIDToken(signature)) {
//				resultMap.putAll(mapper.readValue(alg, HashMap.class));
//				resultMap.putAll(mapper.readValue(jwt, HashMap.class));
				return resultMap;
			} else {
				resultMap.put("error", "Verification signature failure");
				return resultMap;
			}
		} catch (Exception ex) {
			this.logger.info("Could not decode ID token: " + ex.getClass()
					+ ", " + ex.getMessage());
			return Collections.<String, Object> singletonMap("error",
					"Could not decode ID token");
		}

	}

	private OAuth2Authentication extractAuthentication(Map<String, Object> map) {

		String username = (String) map.get(USER_NAME);
		
		// construct authoritiess
		List<SimpleGrantedAuthority> authorities = null;
		@SuppressWarnings("unchecked")
		List<String> blueGroupList = (List<String>) map.get(BLUE_GROUPS);
		if (null != blueGroupList && !blueGroupList.isEmpty()) {
			authorities = new ArrayList<SimpleGrantedAuthority>();
			for (String blueGroup : blueGroupList) {
				if(blueGroup.contains("%20")){
					blueGroup = blueGroup.replace("%20", " ");
				}
				SimpleGrantedAuthority authority = new SimpleGrantedAuthority(blueGroup);
				authorities.add(authority);
			}
		}
		
		User account = new User(username,"",authorities);
		OAuth2Request request = new OAuth2Request(null, restTemplate.getResource().getClientId(), null, true, null, null, null, null, null);
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(account, "N/A", authorities);
		token.setDetails(map);

		return new OAuth2Authentication(request, token);
	}

}
