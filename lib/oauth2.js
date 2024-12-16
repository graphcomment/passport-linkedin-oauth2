var util = require('util');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;

var profileUrl = 'https://api.linkedin.com/v2/me';
var emailUrl =
    'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))';

function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL =
        options.authorizationURL ||
        'https://www.linkedin.com/oauth/v2/authorization';
    options.tokenURL =
        options.tokenURL || 'https://www.linkedin.com/oauth/v2/accessToken';
    options.scope = options.scope || ['profile', 'email', 'openid'];

    OAuth2Strategy.call(this, options, verify);

    this.options = options;
    this.name = 'linkedin';
    this.profileUrl = profileUrl;
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = function (accessToken, done) {
    this._oauth2.useAuthorizationHeaderforGET(true);

    this._oauth2.get(this.profileUrl, accessToken, (err, body) => {
        if (err) {
            return done(new InternalOAuthError('failed to fetch user profile', err));
        }

        let profile;
        try {
            profile = parseProfile(body);
        } catch (e) {
            return done(new InternalOAuthError('failed to parse profile', e));
        }

        this._oauth2.get(emailUrl, accessToken, (err, body) => {
            if (err) {
                return done(new InternalOAuthError('failed to fetch user email', err));
            }

            try {
                const emailJson = JSON.parse(body);
                profile.email =
                    emailJson.elements?.[0]?.['handle~']?.emailAddress || null;
            } catch (e) {
                return done(
                    new InternalOAuthError('failed to parse email response', e)
                );
            }

            done(null, profile);
        });
    });
};

function parseProfile(body) {
    var json = JSON.parse(body);

    return {
        provider: 'linkedin',
        id: json.id,
        givenName: json.localizedFirstName,
        familyName: json.localizedLastName,
        displayName: `${json.localizedFirstName} ${json.localizedLastName}`,
        _raw: body,
        _json: json,
    };
}

module.exports = Strategy;