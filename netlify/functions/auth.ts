import { Handler } from '@netlify/functions';
import cookie from 'cookie';
import { createHash, randomBytes } from 'crypto';

const CLIENT_ID = process.env.SOUNDCLOUD_CLIENT_ID;
const CLIENT_SECRET = process.env.SOUNDCLOUD_CLIENT_SECRET;
const REDIRECT_URI = 'https://lively-mandazi-675d66.netlify.app/.netlify/functions/auth';

// Base64URL encode a Buffer
const base64URLEncode = (buffer: Buffer): string => {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

// Create SHA256 hash and return base64URL encoded string
const sha256 = (buffer: Buffer): string => {
  return createHash('sha256').update(buffer).digest();
};

const handler: Handler = async (event) => {
  // Only allow GET requests
  if (event.httpMethod !== 'GET') {
    return {
      statusCode: 405,
      body: 'Method Not Allowed',
    };
  }

  const { code, state, error } = event.queryStringParameters || {};

  // Handle any OAuth errors
  if (error) {
    console.error('OAuth error:', error);
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Authorization failed' }),
    };
  }

  // If no code is present, initiate the OAuth flow
  if (!code) {
    // Generate code verifier
    const codeVerifier = base64URLEncode(randomBytes(32));
    
    // Generate code challenge
    const codeChallenge = base64URLEncode(sha256(Buffer.from(codeVerifier)));
    
    // Store code verifier in a cookie
    const verifierCookie = cookie.serialize('code_verifier', codeVerifier, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 60 * 5, // 5 minutes
    });

    // Construct the authorization URL with PKCE parameters
    const authUrl = new URL('https://secure.soundcloud.com/authorize');
    authUrl.searchParams.append('client_id', CLIENT_ID!);
    authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');

    return {
      statusCode: 302,
      headers: {
        'Location': authUrl.toString(),
        'Set-Cookie': verifierCookie,
        'Cache-Control': 'no-cache',
      },
      body: 'Redirecting to SoundCloud...',
    };
  }

  try {
    // Get the stored code verifier from cookie
    const cookies = cookie.parse(event.headers.cookie || '');
    const codeVerifier = cookies.code_verifier;

    if (!codeVerifier) {
      throw new Error('Code verifier not found');
    }

    // Exchange the authorization code for an access token
    const tokenResponse = await fetch('https://secure.soundcloud.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json; charset=utf-8',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID!,
        client_secret: CLIENT_SECRET!,
        redirect_uri: REDIRECT_URI,
        code,
        code_verifier: codeVerifier,
      }).toString(),
    });

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.text();
      console.error('Token exchange failed:', errorData);
      throw new Error(`Token exchange failed: ${tokenResponse.statusText}`);
    }

    const { access_token, refresh_token } = await tokenResponse.json();

    // Clear the code verifier cookie
    const clearVerifierCookie = cookie.serialize('code_verifier', '', {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 0,
    });

    // Set secure HTTP-only cookies for tokens
    const cookieSettings = {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 30 * 24 * 60 * 60, // 30 days
    };

    const cookies = [
      cookie.serialize('sc_access_token', access_token, cookieSettings),
      cookie.serialize('sc_refresh_token', refresh_token, cookieSettings),
      clearVerifierCookie,
    ];

    // Redirect back to the main application
    return {
      statusCode: 302,
      headers: {
        'Location': '/',
        'Set-Cookie': cookies,
        'Cache-Control': 'no-cache',
      },
      body: 'Redirecting...',
    };
  } catch (error) {
    console.error('Token exchange error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Failed to exchange token' }),
    };
  }
};

export { handler };