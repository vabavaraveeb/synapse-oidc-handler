package eu.vabavara.synapse.handlers.oidc;

import java.util.HashMap;
import java.util.Map;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.Handler;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;

public class OIDCAuthenticationHandler implements ManagedLifecycle, Handler {
	private static final String CONSUMER_KEY_HEADER = "Bearer";
	private static final String OAUTH_TRUSTED_ISSUERS = "trustedOauth2Issuers";
	private static final String OAUTH_KEYWS_URIS = "keywsUris";
	private static final String OAUTH_AUDIENCE = "expectedAudience";
	private static final String CLAIM_APPID = "appid";
	private static final String CLAIM_SCOPE = "scope";
	private static final String OUT_CLAIM_APPID = "claim_appid";
	private static final String OUT_CLAIM_SUB = "claim_sub";
	private static final String OUT_CLAIM_SCOPE = "claim_scope";
	private static final String OUT_CLAIM_JWT = "claim_jwt";
	private static final String OUT_CLAIM_AUDIENCE = "claim_aud";

	private ConfigurationContext configContext;
	private static final Log log = LogFactory.getLog(OIDCAuthenticationHandler.class);

	private Map<String, Object> properties = new HashMap<String, Object>(2);
	private String keywsUris = null;
	private String trustedOauth2Issuers = null;
	private String expectedAudience = null;

	public void setKeywsUris(String keywsUris) {
		this.keywsUris = keywsUris;
	}
	
	public void setTrustedOauth2Issuers(String issuers) {
		this.trustedOauth2Issuers = issuers;
	}
	
	public void setExpectedAudience(String audience) {
		this.expectedAudience = audience;
	}
	
	public void destroy() {
		this.configContext = null;
	}

	public void init(SynapseEnvironment arg0) {
		try {
			this.configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
		} catch (AxisFault axisFault) {
			log.error("Error occurred while initializing Configuration Context", axisFault);
		}
	}

	public void addProperty(String key, Object value) {
		if (this.properties.containsKey(key))
			this.properties.replace(key, value);
		else
			this.properties.put(key, value);
	}
	
	public Map<String, Object> getProperties() {
		return this.properties;
	}
	
	public void removeProperty(String key) {
		if(this.properties.containsKey(key))
			this.properties.remove(key);
	}

	public boolean handleRequest(MessageContext msgCtx) {
		if (this.getConfigContext() == null) {
			log.error("Configuration Context is null");
			sendErrorMessage(msgCtx);
			return false;
		}
		try {
			// Read parameters from axis2.xml
			if(this.trustedOauth2Issuers == null)
				this.trustedOauth2Issuers = msgCtx.getConfiguration().getAxisConfiguration().getParameter(OAUTH_TRUSTED_ISSUERS).getValue().toString();
			if (this.keywsUris == null)
				this.keywsUris = msgCtx.getConfiguration().getAxisConfiguration().getParameter(OAUTH_KEYWS_URIS)
					.getValue().toString();
			if (this.expectedAudience == null && msgCtx.getConfiguration().getAxisConfiguration().getParameter(OAUTH_AUDIENCE) != null)
				this.expectedAudience = msgCtx.getConfiguration().getAxisConfiguration().getParameter(OAUTH_AUDIENCE).getValue().toString();

			Map headers = (Map) ((Axis2MessageContext) msgCtx).getAxis2MessageContext()
					.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
			String authHeader = (String) headers.get(HttpHeaders.AUTHORIZATION);
			if (authHeader == null) {
				log.warn("Authorization header is missing!");
				sendErrorMessage(msgCtx);
				return false;
			}
			if (!authHeader.startsWith(CONSUMER_KEY_HEADER)) {
				log.warn("Authorization header is invalid!");
				sendErrorMessage(msgCtx);
				return false;
			}
			String accessToken = authHeader.substring(CONSUMER_KEY_HEADER.length()).trim();

			// The HttpsJwks retrieves and caches keys from a the given HTTPS JWKS endpoint.
			// Because it retains the JWKs after fetching them, it can and should be reused
			// to improve efficiency by reducing the number of outbound calls the the
			// endpoint.
			HttpsJwks httpsJkws = new HttpsJwks(this.keywsUris);

			// The HttpsJwksVerificationKeyResolver uses JWKs obtained from the HttpsJwks
			// and will select the
			// most appropriate one to use for verification based on the Key ID and other
			// factors provided
			// in the header of the JWS/JWT.
			HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

			// Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
			// be used to validate and process the JWT.
			// The specific validation requirements for a JWT are context dependent,
			// however,
			// it typically advisable to require a (reasonable) expiration time, a trusted
			// issuer, and
			// and audience that identifies your system as the intended recipient.
			// If the JWT is encrypted too, you need only provide a decryption key or
			// decryption key resolver to the builder.
			JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder().setRequireExpirationTime() // the JWT must have an
																							// expiration time
					.setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account
														// for clock skew
					.setExpectedIssuer(true, this.trustedOauth2Issuers) // check for issuer match
					.setVerificationKeyResolver(httpsJwksKeyResolver) // verify the signature with the public key
					.setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
							ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256); // which is only RS256 here
			if(this.expectedAudience != null)
				jwtConsumerBuilder = jwtConsumerBuilder.setExpectedAudience(true, this.expectedAudience);
					
			JwtConsumer jwtConsumer = jwtConsumerBuilder.build();// create the JwtConsumer instance

			try {
				// Validate the JWT and process it to the Claims
				JwtClaims jwtClaims = jwtConsumer.processToClaims(accessToken);
				log.info("JWT validation succeeded! " + jwtClaims);

				org.apache.axis2.context.MessageContext a2msgCtx = ((Axis2MessageContext) msgCtx).getAxis2MessageContext();
				
				a2msgCtx.setProperty(OUT_CLAIM_JWT, accessToken);
				a2msgCtx.setProperty(OUT_CLAIM_APPID, jwtClaims.getClaimValueAsString(CLAIM_APPID));
				if (jwtClaims.hasClaim("sub"))
					a2msgCtx.setProperty(OUT_CLAIM_SUB, jwtClaims.getSubject());
				if (jwtClaims.hasClaim(CLAIM_SCOPE))
					a2msgCtx.setProperty(OUT_CLAIM_SCOPE, jwtClaims.getClaimValueAsString(CLAIM_SCOPE));
				if (jwtClaims.hasAudience())
					a2msgCtx.setProperty(OUT_CLAIM_AUDIENCE, String.join(" ", jwtClaims.getAudience()));
			} catch (InvalidJwtException e) {
				// InvalidJwtException will be thrown, if the JWT failed processing or
				// validation in anyway.
				// Hopefully with meaningful explanations(s) about what went wrong.
				log.warn("Invalid JWT! " + e);

				// Programmatic access to (some) specific reasons for JWT invalidity is also
				// possible
				// should you want different error handling behavior for certain conditions.

				// Whether or not the JWT has expired being one common reason for invalidity
				if (e.hasExpired()) {
					log.warn("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
				}

				// Or maybe the audience was invalid
				if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
					log.warn("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
				}
				sendErrorMessage(msgCtx);

				return false;
			}

			return true;
		} catch (Exception e) {
			log.error("Error occurred while processing the message", e);
			return false;
		}
	}

	private void sendErrorMessage(MessageContext msgCtx) {
		((Map) ((Axis2MessageContext) msgCtx).getAxis2MessageContext()
				.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).clear();
		((Axis2MessageContext) msgCtx).getAxis2MessageContext().setProperty("HTTP_SC", HttpStatus.SC_UNAUTHORIZED);
		((Axis2MessageContext) msgCtx).getAxis2MessageContext().setProperty("NO_ENTITY_BODY", Boolean.TRUE);
		msgCtx.setProperty("RESPONSE", "true");
		msgCtx.setTo(null);
		Axis2Sender.sendBack(msgCtx);
	}

	public boolean handleResponse(MessageContext msgCtx) {
		return true;
	}

	private ConfigurationContext getConfigContext() {
		return configContext;
	}
}
