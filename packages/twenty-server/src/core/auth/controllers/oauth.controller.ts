import { Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';

import { Request, Response } from 'express';

import { AuthService } from 'src/core/auth/services/auth.service';
import { TokenService } from 'src/core/auth/services/token.service';

@Controller('oauth')
export class OauthController {
  constructor(
    private readonly authService: AuthService,
    private readonly tokenService: TokenService,
  ) {}

  @Get('authorize')
  async authorize(@Req() req: Request, @Res() res: Response, @Query() query) {
    const { response_type, client_id, redirect_uri, scope, state } = query;

    if (response_type !== 'code') {
      return res.status(400).send('Unsupported response_type');
    }

    if (!this.authService.validateClient(client_id, redirect_uri)) {
      return res.status(400).send('Invalid client_id or redirect_uri');
    }

    // Check if the user is already authenticated
    let workspace;

    try {
      workspace = await this.tokenService.validateToken(req);
      console.log('toto', workspace);
    } catch (err) {
      // Redirect to your existing sign-in page, passing along the OAuth2 parameters
      return res.redirect(
        `http://localhost:3001/sign-in?redirect_uri=${encodeURIComponent(
          `http://localhost:3000/oauth/authorize?response_type=${response_type}&client_id=${client_id}&redirect_uri=${redirect_uri}&scope=${scope}&state=${state}`,
        )}`,
      );
    }

    /*    if (!req.query.user_consent) {
      return res.redirect(`/consent?client_id=${client_id}&scope=${scope}`);
    }*/

    /*// Check if user granted consent
    if (req.query.user_consent !== 'true') {
      return res.redirect(`${redirect_uri}?error=access_denied`);
    }*/

    // User has granted consent, generate authorization code or access token
    const code = this.authService.generateAuthorizationCode(
      client_id,
      workspace,
      scope,
    );

    console.log('*******************');

    const redirectUrl = `${redirect_uri}?code=${code}&state=${state}`;

    console.log(code);
    console.log(redirectUrl);

    console.log(redirectUrl);

    return res.redirect(redirectUrl);

    // Implement your sign-in logic here, possibly redirecting to your existing sign-in page
    // Once the user is authenticated, display the consent page
    // If the user approves, redirect back to the client with the authorization code or token
  }

  @Post('accessToken')
  async getAccessToken(
    @Body()
    body: {
      code: string;
      redirectUri: string;
      clientId: string;
      clientSecret: string;
    },
    @Res() res: Response,
  ) {
    if (!body.code) {
      return res.status(400).send('Authorization code is required');
    }

    try {
      // Exchange the authorization code for an access token
      const token = this.authService.exchangeCodeForToken(
        body.code,
        body.redirectUri,
        body.clientId,
        body.clientSecret,
      );

      // Return the token or do something with it
      res.json(token);
    } catch (error) {
      // Handle any errors that occur during the token exchange
      return res
        .status(500)
        .send('Failed to exchange authorization code for token');
    }
  }
}
