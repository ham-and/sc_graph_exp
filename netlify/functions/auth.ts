import { Handler } from '@netlify/functions';
import cookie from 'cookie';

const CLIENT_ID = process.env.SOUNDCLOUD_CLIENT_ID;
const CLIENT_SECRET = process.env.SOUNDCLOUD_CLIENT_SECRET;
const REDIRECT_URI = 'https://lively-mandazi-675d66.netlify.app/.netlify/functions/auth';

const handler: Handler = async (event) => {
  // Only allow GET requests
  if (event.httpMethod !== 'GET') {
    return {
      statusCode: 405,
      body: 'Method Not Allowed',
    };
  }

  const { code, state } = event.queryStringParameters || {};

  if (!code) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Authorization code is required' }),
    };
  }

  try {
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
      }).toString(),
    });

    if (!tokenResponse.ok) {
      throw new Error(`Token exchange failed: ${tokenResponse.statusText}`);
    }

    const { access_token, refresh_token } = await tokenResponse.json();

    // Set secure HTTP-only cookies
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