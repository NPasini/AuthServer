'use strict';

const functions = require('firebase-functions');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const OAUTH_REDIRECT_URI = `https://${process.env.GCLOUD_PROJECT}.firebaseapp.com/authentication.html`;
const AUTHORIZED_REDIRECT_URI = `https://${process.env.GCLOUD_PROJECT}.firebaseapp.com/authorized`;
const OAUTH_SCOPES = 'basic';

function instagramOAuth2Client() {
    // Instagram OAuth 2 setup
    const credentials = {
        client: {
            id: functions.config().instagram.client_id,
            secret: functions.config().instagram.client_secret,
        },
        auth: {
            tokenHost: 'https://api.instagram.com',
            tokenPath: '/oauth/access_token',
        },
    };
    return require('simple-oauth2').create(credentials);
}

exports.redirect = functions.https.onRequest((req, res) => {
    const oauth2 = instagramOAuth2Client();

    cookieParser()(req, res, () => {
        const state = req.cookies.state || crypto.randomBytes(20).toString('hex');
        console.log('Setting verification state:', state);
        res.cookie('state', state.toString(), {
            maxAge: 3600000,
            secure: true,
            httpOnly: true,
        });
        const redirectUri = oauth2.authorizationCode.authorizeURL({
            redirect_uri: OAUTH_REDIRECT_URI,
            scope: OAUTH_SCOPES,
            state: state,
        });
        console.log('Redirecting to:', redirectUri);
        res.redirect(redirectUri);
    });
});

exports.token = functions.https.onRequest((req, res) => {
    const oauth2 = instagramOAuth2Client();

    cookieParser()(req, res, () => {
        console.log('Received verification state:', req.cookies.state);
        console.log('Received state:', req.query.state);

        return oauth2.authorizationCode.getToken({
            code: req.query.code,
            redirect_uri: OAUTH_REDIRECT_URI
        }).then(results => {
            console.log('Auth code exchange result received:', results);
            const accessToken = results.access_token;
            const redirectUrl = AUTHORIZED_REDIRECT_URI + "?accessToken=" + accessToken;
            console.log('Redirecting to:', redirectUrl);
            res.redirect(redirectUrl.toString());
        }).catch(error => {
            res.jsonp({
                error: error.toString(),
            });
        })

    });
});