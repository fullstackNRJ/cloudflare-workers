export interface Env {
	SPREADSHEET_ID: string;
	SERVICE_EMAIL: string;
	PRIVATE_KEY: string;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const path = url.pathname.split('/');

		const action = path[1]; // 'add' or 'update'

		if (action === 'add') {
			const requestData = await request.json();
			console.log('>>>> request', requestData);
			const response = await addRow(requestData, env);
			return new Response(JSON.stringify(response), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		} else if (action === 'update') {
			const rowIndex = parseInt(path[2]); // Row index to update
			const requestData = await request.json();
			console.log('>>>> request', requestData);
			const response = await updateRow(rowIndex, requestData, env);
			return new Response(JSON.stringify(response), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		return new Response('Invalid request', { status: 400 });
	},
};

const encoder = new TextEncoder();

function base64UrlEncode(arrayBuffer: ArrayBuffer) {
	const base64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
	return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function createJWT(env: Env) {
	const header = {
		alg: 'RS256',
		typ: 'JWT',
	};

	const serviceEmail = env.SERVICE_EMAIL;
	const privateKey = env.PRIVATE_KEY;

	const iat = Math.floor(Date.now() / 1000);
	const exp = iat + 3600; // 1 hour expiration
	const payload = {
		iss: serviceEmail,
		sub: serviceEmail,
		scope: 'https://www.googleapis.com/auth/spreadsheets',
		aud: 'https://oauth2.googleapis.com/token',
		iat: iat,
		exp: exp,
	};

	const encodedHeader = base64UrlEncode(encoder.encode(JSON.stringify(header)));
	const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
	const signatureInput = `${encodedHeader}.${encodedPayload}`;

	const key = await crypto.subtle.importKey(
		'pkcs8',
		str2ab(atob(privateKey.replace(/-----\w+ PRIVATE KEY-----/g, '').replace(/\n/g, ''))),
		{
			name: 'RSASSA-PKCS1-v1_5',
			hash: { name: 'SHA-256' },
		},
		false,
		['sign']
	);

	const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(signatureInput));

	const encodedSignature = base64UrlEncode(signature);
	return `${signatureInput}.${encodedSignature}`;
}

function str2ab(str: string) {
	const buf = new ArrayBuffer(str.length);
	const bufView = new Uint8Array(buf);
	for (let i = 0; i < str.length; i++) {
		bufView[i] = str.charCodeAt(i);
	}
	return buf;
}

async function fetchAccessToken(jwt: string) {
	const response = await fetch('https://oauth2.googleapis.com/token', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: new URLSearchParams({
			grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
			assertion: jwt,
		}),
	});
	const data = await response.json();
	return data.access_token;
}

async function addRow(requestData: any, env: Env) {
	//console.log('>>>> requestData', requestData);
	const data = {
		values: [requestData.values], // Expecting requestData.values to be an array of values for the new row
	};
	const response = await googleSheetsAPI('append', data, env);
	const rowIndex = extractRowIndex(response);
	return { response, rowIndex };
}

async function updateRow(rowIndex: number, requestData: any, env: Env) {
	const data = {
		range: `Sheet1!A${rowIndex}:C${rowIndex}`,
		values: [requestData.values], // Expecting requestData.values to be an array of values for the row to update
	};
	const response = await googleSheetsAPI('update', data, env);
	return response;
}

function extractRowIndex(response: any) {
	const updatedRange = response.updates.updatedRange;
	const match = updatedRange.match(/!A(\d+):/);
	if (match && match[1]) {
		return parseInt(match[1]);
	}
	return null;
}

async function googleSheetsAPI(method: string, data: any, env: Env) {
	//const serviceAccount = JSON.parse(env.SERVICE_ACCOUNT_KEY); // Paste your JSON key here
	const jwt = await createJWT(env);
	//console.log('JWT', jwt);
	const accessToken = await fetchAccessToken(jwt);
	//console.log('accessToken', accessToken);
	//const spreadsheetId = '1vujTeqkyaWJSgVTeGt2hAWT4RJgCnjt1KbeLcesYLp8'; // Replace with your Google Sheet ID
	const spreadsheetId = env.SPREADSHEET_ID;

	let url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/Sheet1!A2:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`;
	let options = {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${accessToken}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(data),
	};

	if (method === 'update') {
		url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${data.range}?valueInputOption=RAW`;
		options = {
			method: 'PUT',
			headers: {
				Authorization: `Bearer ${accessToken}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ values: data.values }),
		};
	}

	const response = await fetch(url, options);
	if (!response.ok) {
		const text = await response.text(); // Get the response text
		console.error(`Error: ${response.status} ${response.statusText}`, text);
		throw new Error(`Request failed with status ${response.status}: ${text}`);
	}
	try {
		return await response.json();
	} catch (error) {
		const text = await response.text(); // Get the response text if JSON parsing fails
		console.error('Failed to parse JSON response:', text);
		throw new Error('Failed to parse JSON response');
	}
}
