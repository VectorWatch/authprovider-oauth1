var util = require('util');
var AuthProviderAbstract = require('vectorwatch-authprovider-abstract');
var Promise = require('bluebird');
var url = require('url');
var OAuth = require('oauth').OAuth;

/**
 * @param storageProvider {StorageProviderAbstract}
 * @param options {Object}
 * @constructor
 * @augments AuthProviderAbstract
 */
function OAuth1Provider(storageProvider, options) {
    AuthProviderAbstract.call(this, storageProvider);

    if (process.env.SERVICE_ID) {
        this.options.callbackUrl = "https://apps.vectorwatch.com/" + process.env.SERVICE_ID + "/webhook"
    }

    this.setOptions(options, [
        'consumerKey', 'consumerSecret',
        'requestTokenUrl', 'accessTokenUrl',
        'callbackUrl'
    ]);

    this.protocol = 'OAuth';
    this.version = '1.0';

    this.client = new OAuth(
        this.options.requestTokenUrl,
        this.options.accessTokenUrl,
        this.options.consumerKey,
        this.options.consumerSecret,
        '1.0',
        this.options.callbackUrl,
        this.options.signatureAlgorithm || 'HMAC-SHA1'
    );
}
util.inherits(OAuth1Provider, AuthProviderAbstract);

/**
 * Sets the options and checks the required ones
 * @param options {Object}
 * @param required {String[]}
 */
OAuth1Provider.prototype.setOptions = function(options, required) {
    this.options = {};
    var optionNames = Object.keys(options), _this = this;
    required.forEach(function(requiredOptionName) {
        if (optionNames.indexOf(requiredOptionName) < 0) {
            throw new Error('Option ' + requiredOptionName + ' is required.');
        }
    });

    optionNames.forEach(function(optionName) {
        _this.options[optionName] = options[optionName];
    });
};

/**
 * @inheritdoc
 */
OAuth1Provider.prototype.getAuthTokensAsync = function(credentials) {
    var _this = this;
    var credentialsKey = this.getCredentialsKey(credentials);

    if (!credentialsKey) {
        return Promise.resolve();
    }
    var oauth_token = credentials.oauth_token || credentials.token;
    var oauth_verifier = credentials.oauth_verifier || credentials.verifier;

    if (!oauth_token || !oauth_verifier) return Promise.resolve();

    return this.getStorageProvider().getAuthTokensByCredentialsKeyAsync(credentialsKey).then(function(authTokens) {
        if (!authTokens) return Promise.resolve();

        if (authTokens.oauth_access_token && authTokens.oauth_verifier == oauth_verifier) {
            return {
                oauth_access_token: authTokens.oauth_access_token,
                oauth_access_token_secret: authTokens.oauth_access_token_secret
            };
        }

        return new Promise(function(resolve, reject) {
            _this.client.getOAuthAccessToken(
                oauth_token, authTokens.oauth_token_secret, oauth_verifier,
                function(err, oauth_access_token, oauth_access_token_secret) {
                    if (err) return reject(err);

                    authTokens.oauth_access_token = oauth_access_token;
                    authTokens.oauth_access_token_secret = oauth_access_token_secret;
                    authTokens.oauth_verifier = oauth_verifier;

                    resolve(authTokens);
                }
            );
        }).then(function(authTokens) {
            return _this.getStorageProvider().storeAuthTokensAsync(credentialsKey, authTokens).then(function () {
                return {
                    oauth_access_token: authTokens.oauth_access_token,
                    oauth_access_token_secret: authTokens.oauth_access_token_secret
                };
            });
        })
    });
};

/**
 * @inheritdoc
 */
OAuth1Provider.prototype.getCredentialsKey = function(credentials) {
    if (!credentials || (!credentials.oauth_token && !credentials.token)) {
        return null;
    }

    var hmac = require('crypto').createHmac('sha1', this.options.consumerSecret);
    hmac.update(JSON.stringify((credentials || {}).oauth_token || (credentials || {}).token || ''));
    return hmac.digest('hex');
};

/**
 * @inheritdoc
 */
OAuth1Provider.prototype.getLoginUrlAsync = function() {
    var _this = this;
    return new Promise(function(resolve, reject) {
        _this.client.getOAuthRequestToken(function(err, oauth_token, oauth_token_secret) {
            if (err) return reject(err);

            resolve({
                oauth_token: oauth_token,
                oauth_token_secret: oauth_token_secret
            });
        });
    }).then(function(partialAuthTokens) {
        var credentialsKey = _this.getCredentialsKey(partialAuthTokens);
        return _this.storageProvider.storeAuthTokensAsync(credentialsKey, partialAuthTokens).then(function() {
            var parsedUrl = url.parse(_this.options.authorizeUrl, true);
            parsedUrl.query.oauth_token = partialAuthTokens.oauth_token;
            delete parsedUrl.search;

            return url.format(parsedUrl);
        });
    });
};

module.exports = OAuth1Provider;