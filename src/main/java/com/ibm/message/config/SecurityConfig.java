package com.ibm.message.config;
import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import com.ibm.message.support.OpenIDTokenService;

@Configuration
@EnableOAuth2Client
//@Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private @Autowired OAuth2ClientContext clientContext;
	private @Autowired AuthorizationCodeResourceDetails authorizationCodeResourceDetails;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		auth.inMemoryAuthentication().withUser("szwbwang@cn.ibm.com").password("123456").roles("com.ibm.tap.admin");
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		// TODO Auto-generated method stub
		super.configure(web);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// TODO Auto-generated method stub
		http.authorizeRequests().antMatchers("/login").permitAll()
		.and().authorizeRequests().anyRequest().authenticated();
		
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/welcome");
		//filter.setSessionAuthenticationStrategy(http.getSharedObject(SessionAuthenticationStrategy.class));
		
		OAuth2RestTemplate oauth2RestTemplate  = new OAuth2RestTemplate(authorizationCodeResourceDetails,clientContext);
		filter.setRestTemplate(oauth2RestTemplate);
		filter.setTokenServices(new OpenIDTokenService(oauth2RestTemplate));
		
		http.addFilterBefore(filter, BasicAuthenticationFilter.class)
		.exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
		
		http.cors().and().csrf().ignoringAntMatchers("/ws/**");
	}
}
