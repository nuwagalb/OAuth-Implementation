'use strict';
//1.add all modules to be used in our app
let express = require("express");
let bodyParser = require('body-parser');
let request = require("sync-request");
let url = require("url");
let qs = require("qs");
let querystring = require('querystring');
let cons = require('consolidate');
let randomstring = require("randomstring");
let jose = require('jsrsasign');
let base64url = require('base64url');
let __ = require('underscore');
__.string = require('underscore.string');

//2. create a new instance of the express web framework module
//so we can begin constructing our app
let app = express();

//3. using the bodyParser middleware, setup how our app will work
app.use(bodyParser.json()); //our app should only parse json data
app.use(bodyParser.urlencoded({extended: true})); //our app should encode data passed in our url

//4.for our templating needs
app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'ui/client');

//5.authorization server information: information to send to our authorization server from our client
let authServer = {
    authorizationEndpoint: 'http://localhost:9003/authorize',
    tokenEndpoint: 'http://localhost:9003/token'
}

//
let rsaKey = {
    "alg": "RS256",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "authserver"
}

//6. Our Client information (Globomantics Information)
let client = {
	"client_id": "globomantics-client-1",
	"client_secret": "globomantics-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"],
	"scope": "visits membershipTime averageWorkoutLength"
};

let carvedRockGymApi = 'http://localhost:9002/gymStats';

let state = null;

let access_token = null;
let refresh_token = null;
let scope = null;

app.get('/', function (req,res) {
    res.render('index', {access_token: access_token, refresh_token: refresh_token, 
    scope: scope});
}); //end app.get('/')

app.get('/authorize', function (req, res) {
    access_token = null;
    refresh_token = null;
    scope = null;
    state = randomstring.generate();

    let authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
        response_type: 'code',
        scope: client.scope,
        client_id: client.client_id,
        redirect_uri: client.redirect_uris[0],
        state: state
    });

    console.log("redirect", authorizeUrl);
    res.redirect(authorizeUrl);
}); //end app.get('/authorize');

app.get("/callback", function (req, res) {
    if (req.query.error) {
        //if error is generated, act accordingly
        //req.query returns a JS Object
        res.render('error', {error: req.query.error});
    }

    let resState = req.query.state;

    if(resState === state) {
        console.log('State value matches: expected %s got %s', state, resState);
    } else {
        console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
		res.render('error', {error: 'State value did not match'});
		return;
    }

    let code = req.query.code;

    let form_data = qs.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: client.redirect_uris[0]     
    });

    let headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + Buffer.from(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64') 
    };

    let tokRes = request('POST', authServer.tokenEndpoint,
        {
            body: form_data,
            headers: headers
        }
    );

    console.log('Requesting access token for code %s',code);

    if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
        let body = JSON.parse(tokRes.getBody());

        access_token = body.access_token;
        console.log('Got access token: %s', access_token);

        if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log('Got refresh token: %s', refresh_token);
		}

        if (body.access_token) {
            console.log('Got access token: %s', body.access_token);

            //check the access token
            let pubKey = jose.KEYUTIL.getKey(rsaKey);
			let signatureValid = jose.jws.JWS.verify(body.access_token, pubKey, ['RS256']);

            if (signatureValid) {
                console.log('Signature validated');
                let tokenParts = body.access_token.split('');
                let payload = JSON.parse(base64url.decode(tokenParts[1]));
                console.log('Payload', payload);
                if (payload.iss === 'http://localhost:9003') {
                    console.log('issuer OK');
                    // TODO: this is incorrect. Fix the video and the code
					if ((Array.isArray(payload.aud) && _.contains(payload.aud, 'http://localhost:9002/')) || 
                    payload.aud == 'http://localhost:9002/') {
                        console.log('Audience OK');
                        
                        let now = Math.floor(Date.now() / 1000);

                        if (payload.iat <= now) {
                            console.log('issued-at OK');
                            if (payload.exp >= now) {
                                console.log('expiration OK');
                                console.log('Token valid!');
                            }
                        }
                    }
                }
            }

        }

        scope = body.scope;
        console.log('Got scope: %s', scope);
        res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
    } else {
        res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
    }
}); //end app.get('/callback')

let refreshToken = function (req,res) {
    let form_data = qs.stringify({
        grant_type: 'refresh_token',
        refresh_token: refresh_token,
        client_id: client.client_id,
        client_secret: client.client_secret,
        redirect_uri: client.redirect_uri
    });

    let headers = {
		'Content-Type': 'application/x-www-form-urlencoded'
	};

    console.log('Refreshing token %s', refresh_token);

    let tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);

    if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());

		access_token = body.access_token;
		console.log('Got access token: %s', access_token);
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log('Got refresh token: %s', refresh_token);
		}
		scope = body.scope;
		console.log('Got scope: %s', scope);
	
		// try again
		res.redirect('/gymStats');
		return;
	} else {
		console.log('No refresh token, asking the user to get a new access token');
		// tell the user to get a new access token
		res.redirect('/authorize');
		return;
	}
}; //end of refreshToken()

app.get('/gymStats', function(req, res) {

	if (!access_token) {
		if (refresh_token) {
			// try to refresh and start again
			refreshAccessToken(req, res);
			return;
		} else {
			res.render('error', {error: 'Missing access token.'});
			return;
		}
	}
	
	console.log('Making request with access token %s', access_token);
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('GET', carvedRockGymApi,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('gymStats', {scope: scope, data: body});
		return;
	} else {
		access_token = null;
		if (refresh_token) {
			// try to refresh and start again
			refreshAccessToken(req, res);
			return;
		} else {
			res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
			return;
		}
	}
}); //end of app.get('/gymStats')

//create another middleware for the '/' endpoint
app.use('/', express.static('ui/client'));

//build another url
var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

let server = app.listen(9000, 'localhost', function () {
    var host = server.address().address;
    var port = server.address().port;
    console.log('OAuth Client is listening at http://%s:%s', host, port);
});
   




