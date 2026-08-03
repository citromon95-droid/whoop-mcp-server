import crypto from 'node:crypto';
import type { Express, Request, Response, NextFunction } from 'express';

/**
 * Minimal OAuth 2.1 facade so Claude's custom-connector flow can complete.
 *
 * This server is single-user and private: there is nothing to "log in" to.
 * Claude, however, insists on OAuth discovery + dynamic client registration
 * before it will talk to a remote MCP server, so we implement just enough of
 * the protocol to satisfy it.
 *
 * The issued access token is derived deterministically from WHOOP_CLIENT_SECRET,
 * so it survives redeploys (no reconnect needed) without any extra storage.
 */

export function deriveToken(secret: string): string {
	return crypto.createHash('sha256').update(`whoop-mcp-token:${secret}`).digest('hex');
}

export function registerOAuthStub(app: Express, baseUrl: string, secret: string): void {
	const token = deriveToken(secret);

	const authServerMetadata = {
		issuer: baseUrl,
		authorization_endpoint: `${baseUrl}/authorize`,
		token_endpoint: `${baseUrl}/token`,
		registration_endpoint: `${baseUrl}/register`,
		response_types_supported: ['code'],
		grant_types_supported: ['authorization_code', 'refresh_token'],
		code_challenge_methods_supported: ['S256', 'plain'],
		token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
		scopes_supported: ['mcp'],
	};

	const resourceMetadata = {
		resource: `${baseUrl}/mcp`,
		authorization_servers: [baseUrl],
		scopes_supported: ['mcp'],
		bearer_methods_supported: ['header'],
	};

	// Discovery — Claude probes both the bare paths and /mcp-suffixed variants.
	const authServerPaths = [
		'/.well-known/oauth-authorization-server',
		'/.well-known/oauth-authorization-server/mcp',
		'/.well-known/openid-configuration',
	];
	for (const path of authServerPaths) {
		app.get(path, (_req: Request, res: Response): void => {
			res.json(authServerMetadata);
		});
	}

	const resourcePaths = [
		'/.well-known/oauth-protected-resource',
		'/.well-known/oauth-protected-resource/mcp',
	];
	for (const path of resourcePaths) {
		app.get(path, (_req: Request, res: Response): void => {
			res.json(resourceMetadata);
		});
	}

	// Dynamic client registration — accept anything, hand back a fixed client_id.
	app.post('/register', (req: Request, res: Response): void => {
		const body = (req.body ?? {}) as { redirect_uris?: string[] };
		res.status(201).json({
			client_id: 'whoop-mcp-client',
			client_id_issued_at: Math.floor(Date.now() / 1000),
			redirect_uris: body.redirect_uris ?? [],
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
		});
	});

	// Authorization — auto-approve and bounce straight back with a code.
	app.get('/authorize', (req: Request, res: Response): void => {
		const redirectUri = typeof req.query.redirect_uri === 'string' ? req.query.redirect_uri : '';
		const state = typeof req.query.state === 'string' ? req.query.state : '';

		if (!redirectUri) {
			res.status(400).send('Missing redirect_uri');
			return;
		}

		let target: URL;
		try {
			target = new URL(redirectUri);
		} catch {
			res.status(400).send('Invalid redirect_uri');
			return;
		}

		target.searchParams.set('code', 'whoop-mcp-authorization-code');
		if (state) target.searchParams.set('state', state);
		res.redirect(target.toString());
	});

	// Token — always issue the same long-lived token.
	app.post('/token', (_req: Request, res: Response): void => {
		res.json({
			access_token: token,
			token_type: 'Bearer',
			expires_in: 31_536_000,
			refresh_token: token,
			scope: 'mcp',
		});
	});
}

export function requireBearer(baseUrl: string, secret: string) {
	const expected = `Bearer ${deriveToken(secret)}`;

	return (req: Request, res: Response, next: NextFunction): void => {
		if (req.headers.authorization === expected) {
			next();
			return;
		}

		res
			.status(401)
			.set(
				'WWW-Authenticate',
				`Bearer realm="whoop-mcp", resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`
			)
			.json({ error: 'invalid_token', error_description: 'Missing or invalid access token' });
	};
}
