import type { VercelRequest, VercelResponse } from '@vercel/node';
import whois from 'whois-json';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const domain = req.query.domain as string;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    console.log(`[API] Attempting RDAP fetch for ${domain}`);
    let days = 0;
    let created_date = 'Unknown';
    let registrar = 'Unknown';

    // 1. Try RDAP First (Modern, JSON-native)
    try {
      const rdapRes = await fetch(`https://rdap.org/domain/${domain}`);
      if (rdapRes.ok) {
        const rdapData = await rdapRes.json() as any;
        
        // Parse Registration Event
        if (rdapData.events && Array.isArray(rdapData.events)) {
          const regEvent = rdapData.events.find((e: any) => e.eventAction === 'registration');
          if (regEvent && regEvent.eventDate) {
            const firstSeen = new Date(regEvent.eventDate);
            days = Math.floor((Date.now() - firstSeen.getTime()) / (1000 * 60 * 60 * 24));
            created_date = regEvent.eventDate.substring(0, 10);
          }
        }

        // Parse Registrar
        if (rdapData.entities && Array.isArray(rdapData.entities)) {
           const regEntity = rdapData.entities.find((e: any) => e.roles && e.roles.includes('registrar'));
           if (regEntity && regEntity.vcardArray && regEntity.vcardArray[1]) {
             const fn = regEntity.vcardArray[1].find((v: any) => v[0] === 'fn');
             if (fn) registrar = fn[3];
           }
        }

        if (days > 0) {
          return res.status(200).json({ days, created_date, registrar: registrar || 'RDAP Verified' });
        }
      }
    } catch (e) {
      console.log(`[API] RDAP failed for ${domain}, proceeding to local WHOIS fallback`);
    }

    // 2. Local WHOIS Fallback (Works offline/locally, might be blocked on Vercel port 43)
    try {
      console.log(`[API] Attempting whois-json for ${domain}`);
      const whoisData = await whois(domain) as any;
      
      let creationStr = '';
      if (whoisData) {
        creationStr = whoisData.creationDate || whoisData.created || whoisData.creation_date || whoisData['Creation Date'] || whoisData['Registered on'] || '';
        if (!creationStr) {
          for (const key in whoisData) {
            if (key.toLowerCase().includes('creat') || key.toLowerCase().includes('regist')) {
              const val = String(whoisData[key]);
              if (val.match(/\d{4}/)) {
                creationStr = val;
                break;
              }
            }
          }
        }
        
        if (creationStr) {
           const parsedDate = new Date(creationStr);
           if (!isNaN(parsedDate.getTime())) {
             days = Math.floor((Date.now() - parsedDate.getTime()) / (1000 * 60 * 60 * 24));
             created_date = parsedDate.toISOString().substring(0, 10);
             registrar = whoisData.registrar || whoisData.Registrar || whoisData['Sponsoring Registrar'] || 'whois-json Verified';
             return res.status(200).json({ days, created_date, registrar });
           }
        }
      }
    } catch (err) {
      console.warn(`[API] whois-json failed for ${domain}:`, err);
    }

    // 3. HTTP WHOIS Fallback (To prevent Vercel port 43 blocking)
    // Serverless platforms block TCP port 43, so we must use an HTTP API
    const API_NINJAS_KEY = process.env.API_NINJAS_KEY || process.env.VITE_API_NINJAS_KEY || '';
    
    if (API_NINJAS_KEY) {
      console.log(`[API] Using API Ninjas HTTP WHOIS for ${domain}`);
      try {
        const ninjaRes = await fetch(`https://api.api-ninjas.com/v1/whois?domain=${domain}`, {
          headers: { 'X-Api-Key': API_NINJAS_KEY }
        });
        
        if (ninjaRes.ok) {
          const data = await ninjaRes.json();
          if (data.creation_date) {
             // API Ninjas typically returns unix timestamp
             const firstSeen = new Date(data.creation_date * 1000);
             if (!isNaN(firstSeen.getTime())) {
               days = Math.floor((Date.now() - firstSeen.getTime()) / (1000 * 60 * 60 * 24));
               created_date = firstSeen.toISOString().substring(0, 10);
             }
          }
          registrar = data.registrar || 'Unknown';
          return res.status(200).json({ days, created_date, registrar });
        }
      } catch (e) {
        console.warn('[API] API Ninjas fallback failed:', e);
      }
    } else {
      console.log(`[API] No API_NINJAS_KEY found. Unable to perform HTTP WHOIS fallback for ${domain}.`);
    }

    // Return what we have (even if it's 0 days, the frontend will handle the fallback logic properly)
    return res.status(200).json({ days, created_date, registrar });
  } catch (error) {
    console.error('[API] WHOIS Error:', error);
    return res.status(500).json({ error: 'Failed to fetch domain age' });
  }
}
