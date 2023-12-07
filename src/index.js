import express from 'express';
import querystring from 'querystring';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { COOKIE_NAME, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SECRET, SERVER_ROOT_URL, UI_ROOT_URL } from '../config.js';

const app = express();
const port = 4000;

app.use(
    cors({
        // Sets Access-Control-Allow-Origin to the UI URI
        origin: UI_ROOT_URL,
        // Sets Access-Control-Allow-Credentials to true
        credentials: true,
    })
);

app.use(cookieParser())

const redirectURI = 'auth/google';

function getGoogleAuthURL() {
    const rootUrl = "https://accounts.google.com/o/oauth2/v2/auth";
    const options = {
        redirect_uri: `${SERVER_ROOT_URL}/${redirectURI}`,
        client_id: GOOGLE_CLIENT_ID,
        access_type: "offline",
        response_type: "code",
        prompt: "consent",
        scope: [
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
        ].join(" "),
    }

    return `${rootUrl}?${querystring.stringify(options)}`;
}

// Getting login URL

app.get('/auth/google/url', (request, response) => {
    return response.send(getGoogleAuthURL());
})

function getToken({
    code,
    clientId,
    clientSecret,
    redirectUri,
}) {
    // Uses the code to get token
    // That can be used to fetch the user's profile

    const url = "https://oauth2.googleapis.com/token";
    const values = {
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
    };

    return axios
        .post(url, querystring.stringify(values), {
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
        })
        .then((response) => {
            console.log("Get Token Response", response.data)
            return response.data
        })
        .catch((error) => {
            console.log("Get Token Error", error)
        })
}

// Getting the user from Google with the code

app.get(`/${redirectURI}`, async (request, response) => {
    const code = request.query.code;

    const { id_token, access_token } = await getToken({
        code,
        clientId: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        redirectUri: `${SERVER_ROOT_URL}/${redirectURI}`
    })

    // Fetch the user's profile with the access token and bearer
    const googleUser = await axios
        .get(
            `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${access_token}`,
            {
                headers: {
                    Authorization: `Bearer ${id_token}`
                }
            }
        )
        .then((response) => {
            console.log("Fetch User Response", response.data)
            return response.data
        })
        .catch((error) => {
            console.log("Fetch User Error", error.message)
        })

    const token = jwt.sign(googleUser, JWT_SECRET);

    response.cookie(COOKIE_NAME, token, {
        maxAge: 900000,
        httpOnly: true,
        secure: false,
    })

    response.redirect(UI_ROOT_URL)
})

// Getting the current user
app.get("/auth/me", (req, res) => {
    try {
        const decodedToken = jwt.verify(req.cookies[COOKIE_NAME], JWT_SECRET);
        console.log("decoded", decodedToken);
        return res.send(decodedToken);
    } catch (err) {
        console.log(err);
        res.send(null);
    }
});


app.listen(port, () => console.log("Server Started"))