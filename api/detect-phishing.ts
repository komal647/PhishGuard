import type { VercelRequest, VercelResponse } from '@vercel/node';

interface ThreatIndicator {
  name: string;
  severity: 'low' | 'medium' | 'high';
  description: string;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { urls } = req.body as { urls: string[] };
  if (!urls || !Array.isArray(urls) || urls.length === 0) {
    return res.json({ indicators: [], threat_audit: null, score: 0 });
  }

  // Support both standard variables and Vite-prefixed ones that the user might have provided
  const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_KEY || process.env.VITE_VIRUSTOTAL_KEY || '';
  const GOOGLE_SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || process.env.VITE_GOOGLE_SAFE_BROWSING_KEY || '';
  const PHISHTANK_KEY = process.env.PHISHTANK_KEY || process.env.VITE_PHISHTANK_KEY || '';
  const IPQUALITYSCORE_KEY = process.env.IPQUALITYSCORE_KEY || process.env.VITE_IPQUALITYSCORE_KEY || '';
  const CLOUDMERSIVE_KEY = process.env.CLOUDMERSIVE_KEY || process.env.VITE_CLOUDMERSIVE_KEY || '';
  const URLHAUS_KEY = process.env.URLHAUS_KEY || process.env.VITE_URLHAUS_KEY || '';

  const indicators: ThreatIndicator[] = [];
  let score = 0;
  const threat_audit: { scan_time: string; sources: Record<string, unknown> } = {
    scan_time: new Date().toISOString(),
    sources: {},
  };

  for (const url of urls) {
    const cleanUrl = url.startsWith('http') ? url : `https://${url}`;

    // 1. VirusTotal
    if (VIRUSTOTAL_KEY) {
      try {
        const encodedId = Buffer.from(cleanUrl).toString('base64').replace(/=/g, '');
        const r = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedId}`, {
          method: 'GET',
          headers: { 'x-apikey': VIRUSTOTAL_KEY, 'Accept': 'application/json' },
        });
        if (r.ok) {
          const data = await r.json() as any;
          const stats = data.data?.attributes?.last_analysis_stats;
          if (stats) {
            threat_audit.sources.virustotal = {
              scanned: true, malicious: stats.malicious, suspicious: stats.suspicious,
              verdict: stats.malicious > 0 ? 'malicious' : stats.suspicious > 0 ? 'suspicious' : 'clean',
            };
            if (stats.malicious > 0) {
              indicators.push({ name: 'VirusTotal Flag', severity: 'high', description: `Flagged malicious by ${stats.malicious} security vendors on VT` });
              score += 60;
            } else if (stats.suspicious > 0) {
              indicators.push({ name: 'VirusTotal Suspicious', severity: 'medium', description: `Flagged suspicious by ${stats.suspicious} security vendors on VT` });
              score += 30;
            }
          }
        }
      } catch (e: any) { console.warn('VT Error:', e.message); }
    }

    // 2. Google Safe Browsing
    if (GOOGLE_SAFE_BROWSING_KEY) {
      try {
        const payload = {
          client: { clientId: 'phishguard', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: cleanUrl }],
          },
        };
        const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_KEY}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (r.ok) {
          const data = await r.json() as { matches?: { threatType: string }[] };
          const matches = data.matches || [];
          threat_audit.sources.google_safe_browsing = { scanned: true, matches: matches.map(m => m.threatType) };
          if (matches.length > 0) {
            indicators.push({ name: 'Google Safe Browsing', severity: 'high', description: `Flagged as ${matches[0].threatType}` });
            score += 100;
          }
        }
      } catch (e: any) { console.warn('GSB Error:', e.message); }
    }

    // 3. PhishTank
    if (PHISHTANK_KEY && PHISHTANK_KEY !== 'your_phishtank_key_here') {
      try {
        const r = await fetch('https://checkurl.phishtank.com/checkurl/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ url: cleanUrl, format: 'json', app_key: PHISHTANK_KEY }).toString(),
        });
        if (r.ok) {
          const data = await r.json() as any;
          threat_audit.sources.phishtank = { scanned: true, found: data?.results?.in_database, verified: data?.results?.valid };
          if (data?.results?.valid) {
            indicators.push({ name: 'PhishTank', severity: 'high', description: 'Verified phishing URL in community database.' });
            score += 80;
          }
        }
      } catch (e: any) { console.warn('PhishTank Error:', e.message); }
    }

    // 4. IPQualityScore
    if (IPQUALITYSCORE_KEY) {
      try {
        const r = await fetch(`https://www.ipqualityscore.com/api/json/url/${IPQUALITYSCORE_KEY}/${encodeURIComponent(cleanUrl)}`);
        if (r.ok) {
          const data = await r.json() as any;
          if (data.success && data.unsafe && data.risk_score > 75) {
            const isHighRisk = data.risk_score > 90;
            indicators.push({ name: 'IPQualityScore', severity: isHighRisk ? 'high' : 'medium', description: `IPQS Flagged suspicious (Risk Score: ${data.risk_score})` });
            score += isHighRisk ? 40 : 20;
          }
        }
      } catch (e: any) { console.warn('IPQS Error:', e.message); }
    }

    // 5. Cloudmersive
    if (CLOUDMERSIVE_KEY && CLOUDMERSIVE_KEY !== 'your_cloudmersive_key_here') {
      try {
        const r = await fetch('https://api.cloudmersive.com/virus/scan/website', {
          method: 'POST',
          headers: { 'Apikey': CLOUDMERSIVE_KEY, 'Content-Type': 'application/json' },
          body: JSON.stringify({ Url: cleanUrl }),
        });
        if (r.ok) {
          const data = await r.json() as any;
          if (data.CleanResult === false) {
            indicators.push({ name: 'Cloudmersive', severity: 'high', description: 'Website scanned as malicious/virus.' });
            score += 60;
          }
        }
      } catch (e: any) { console.warn('Cloudmersive Error:', e.message); }
    }

    // 6. URLhaus (Keyless Public API by abuse.ch)
    try {
      const bodyParams = new URLSearchParams({ url: cleanUrl }).toString();
      const r = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: bodyParams,
      });
      if (r.ok) {
        const data = await r.json() as any;
        if (data?.query_status === 'ok' && data?.url_status === 'online') {
          threat_audit.sources.urlhaus = { scanned: true, status: data.url_status, threat: data.threat };
          indicators.push({
            name: 'URLhaus Malware Flag',
            severity: 'high',
            description: `URL is actively tracked as ${data.threat || 'malware/phishing'} by URLhaus`
          });
          score += 85;
        } else if (data?.query_status === 'ok') {
          threat_audit.sources.urlhaus = { scanned: true, status: data.url_status, threat: data.threat };
          indicators.push({
            name: 'URLhaus Historical Flag',
            severity: 'medium',
            description: `URL has history in URLhaus threat database (${data.threat || 'malware'})`
          });
          score += 45;
        } else {
          threat_audit.sources.urlhaus = { scanned: true, found: false };
        }
      }
    } catch (e: any) {
      console.warn('URLhaus Error:', e.message);
    }
  }

  return res.json({
    indicators,
    threat_audit: Object.keys(threat_audit.sources).length > 0 ? threat_audit : null,
    score,
  });
}
