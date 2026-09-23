import type { VercelRequest, VercelResponse } from '@vercel/node';

interface ApiStatus {
  name: string;
  status: 'online' | 'error' | 'missing' | 'testing';
  message?: string;
}

export default async function handler(_req: VercelRequest, res: VercelResponse) {
  // Support both standard variables and Vite-prefixed ones that the user might have provided
  const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_KEY || process.env.VITE_VIRUSTOTAL_KEY || '';
  const GOOGLE_SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || process.env.VITE_GOOGLE_SAFE_BROWSING_KEY || '';
  const PHISHTANK_KEY = process.env.PHISHTANK_KEY || process.env.VITE_PHISHTANK_KEY || '';
  const IPQUALITYSCORE_KEY = process.env.IPQUALITYSCORE_KEY || process.env.VITE_IPQUALITYSCORE_KEY || '';
  const CLOUDMERSIVE_KEY = process.env.CLOUDMERSIVE_KEY || process.env.VITE_CLOUDMERSIVE_KEY || '';
  const URLHAUS_KEY = process.env.URLHAUS_KEY || process.env.VITE_URLHAUS_KEY || '';

  // 1. URLhaus (Keyless Public Security API)
  try {
    const r = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ url: testUrl }).toString(),
    });
    results.push({ name: 'URLhaus (abuse.ch)', status: r.ok ? 'online' : 'error', message: r.ok ? 'Public API Online' : `HTTP Error ${r.status}` });
  } catch (e: any) { results.push({ name: 'URLhaus (abuse.ch)', status: 'error', message: e.message }); }

  // 2. Cloudflare DNS-over-HTTPS
  try {
    const r = await fetch('https://cloudflare-dns.com/dns-query?name=example.com&type=A', {
      headers: { 'Accept': 'application/dns-json' }
    });
    results.push({ name: 'Cloudflare DNS-over-HTTPS', status: r.ok ? 'online' : 'error', message: r.ok ? 'DOH Resolver Active' : `HTTP Error ${r.status}` });
  } catch (e: any) { results.push({ name: 'Cloudflare DNS-over-HTTPS', status: 'error', message: e.message }); }

  // 3. RDAP & Wayback Machine CDX API
  try {
    const r = await fetch('https://rdap.org/domain/example.com');
    results.push({ name: 'RDAP & Wayback CDX', status: r.ok ? 'online' : 'error', message: r.ok ? 'Domain Age Registry Online' : `HTTP Error ${r.status}` });
  } catch (e: any) { results.push({ name: 'RDAP & Wayback CDX', status: 'error', message: e.message }); }

  // 4. VirusTotal (Optional Key)
  if (VIRUSTOTAL_KEY) {
    try {
      const encodedId = Buffer.from(testUrl).toString('base64').replace(/=/g, '');
      const r = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedId}`, {
        method: 'GET', headers: { 'x-apikey': VIRUSTOTAL_KEY, 'Accept': 'application/json' },
      });
      results.push({ name: 'VirusTotal', status: r.ok || r.status === 404 ? 'online' : 'error', message: r.ok || r.status === 404 ? 'Connected API' : `HTTP Error ${r.status}` });
    } catch (e: any) { results.push({ name: 'VirusTotal', status: 'error', message: e.message }); }
  } else { results.push({ name: 'VirusTotal', status: 'missing', message: 'Optional key not set in env' }); }

  // 5. Google Safe Browsing (Optional Key)
  if (GOOGLE_SAFE_BROWSING_KEY) {
    try {
      const payload = { client: { clientId: 'phishguard', clientVersion: '1.0.0' }, threatInfo: { threatTypes: ['MALWARE'], platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url: testUrl }] } };
      const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_KEY}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      });
      results.push({ name: 'Google Safe Browsing', status: r.ok ? 'online' : 'error', message: r.ok ? 'Connected API' : `HTTP Error ${r.status}` });
    } catch (e: any) { results.push({ name: 'Google Safe Browsing', status: 'error', message: e.message }); }
  } else { results.push({ name: 'Google Safe Browsing', status: 'missing', message: 'Optional key not set in env' }); }

  // 6. PhishTank (Optional Key)
  if (PHISHTANK_KEY && PHISHTANK_KEY !== 'your_phishtank_key_here') {
    try {
      const r = await fetch('https://checkurl.phishtank.com/checkurl/', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ url: testUrl, format: 'json', app_key: PHISHTANK_KEY }).toString(),
      });
      results.push({ name: 'PhishTank', status: r.ok ? 'online' : 'error', message: r.ok ? 'Connected API' : `HTTP Error ${r.status}` });
    } catch (e: any) { results.push({ name: 'PhishTank', status: 'error', message: e.message }); }
  } else { results.push({ name: 'PhishTank', status: 'missing', message: 'Optional key not set in env' }); }

  // 7. IPQualityScore (Optional Key)
  if (IPQUALITYSCORE_KEY) {
    try {
      const r = await fetch(`https://www.ipqualityscore.com/api/json/url/${IPQUALITYSCORE_KEY}/${encodeURIComponent(testUrl)}`);
      results.push({ name: 'IPQualityScore', status: r.ok ? 'online' : 'error', message: r.ok ? 'Connected API' : `HTTP Error ${r.status}` });
    } catch (e: any) { results.push({ name: 'IPQualityScore', status: 'error', message: e.message }); }
  } else { results.push({ name: 'IPQualityScore', status: 'missing', message: 'Optional key not set in env' }); }

  // 8. Cloudmersive (Optional Key)
  if (CLOUDMERSIVE_KEY && CLOUDMERSIVE_KEY !== 'your_cloudmersive_key_here') {
    try {
      const r = await fetch('https://api.cloudmersive.com/virus/scan/website', {
        method: 'POST', headers: { 'Apikey': CLOUDMERSIVE_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ Url: testUrl }),
      });
      results.push({ name: 'Cloudmersive', status: r.ok ? 'online' : 'error', message: r.ok ? 'Connected API' : `HTTP Error ${r.status}` });
    } catch (e: any) { results.push({ name: 'Cloudmersive', status: 'error', message: e.message }); }
  } else { results.push({ name: 'Cloudmersive', status: 'missing', message: 'Optional key not set in env' }); }

  return res.json({ results });
}
