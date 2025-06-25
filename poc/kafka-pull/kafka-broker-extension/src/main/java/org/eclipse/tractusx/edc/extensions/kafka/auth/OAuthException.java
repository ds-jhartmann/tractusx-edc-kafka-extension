package org.eclipse.tractusx.edc.extensions.kafka.auth;

import org.eclipse.edc.spi.EdcException;

/**
 * Exception thrown when OAuth operations fail.
 */
public class OAuthException extends EdcException {
    public OAuthException(String message) {
        super(message);
    }

    public OAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
