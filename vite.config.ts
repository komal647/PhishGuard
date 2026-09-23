import { defineConfig, Plugin } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";
import { VitePWA } from "vite-plugin-pwa";
import whois from "whois-json";

// Custom Vite plugin to handle WHOIS and RDAP requests securely via the Node backend during local 'npm run dev'
function whoisPlugin(): Plugin {
  return {
    name: 'whois-plugin',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (req.url?.startsWith('/api/whois')) {
          const url = new URL(req.url, `http://${req.headers.host}`);
          const domain = url.searchParams.get('domain');

          if (!domain) {
            res.statusCode = 400;
            res.end(JSON.stringify({ error: 'Domain parameter is required' }));
            return;
          }

          res.setHeader('Content-Type', 'application/json');

          try {
            console.log(`[Vite] Attempting RDAP fetch for ${domain}`);
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

                if (rdapData.entities && Array.isArray(rdapData.entities)) {
                   const regEntity = rdapData.entities.find((e: any) => e.roles && e.roles.includes('registrar'));
                   if (regEntity && regEntity.vcardArray && regEntity.vcardArray[1]) {
                     const fn = regEntity.vcardArray[1].find((v: any) => v[0] === 'fn');
                     if (fn) registrar = fn[3];
                   }
                }

                if (days > 0) {
                  res.end(JSON.stringify({ days, created_date, registrar: registrar || 'RDAP Verified' }));
                  return;
                }
              }
            } catch (e) {
              console.log(`[Vite] RDAP failed for ${domain}, falling back to WHOIS`);
            }

            // 2. Fallback to raw WHOIS port 43 lookup using `whois-json`
            try {
              console.log(`[Vite] Falling back to traditional WHOIS for ${domain}`);
              const whoisData = await whois(domain) as any;
              
              let creationStr = whoisData['creationDate'] || whoisData['created'] || whoisData['registeredOn'] || whoisData['domainRegistrationDate'] || '';
              
              if (!creationStr && whoisData) {
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
                const firstSeen = new Date(creationStr);
                if (!isNaN(firstSeen.getTime())) {
                   days = Math.floor((Date.now() - firstSeen.getTime()) / (1000 * 60 * 60 * 24));
                   created_date = firstSeen.toISOString().substring(0, 10);
                }
              }

              registrar = whoisData['registrar'] || whoisData['sponsoringRegistrar'] || 'Unknown';
            } catch (whoisErr) {
              console.warn(`[Vite] whois-json failed for ${domain}:`, whoisErr);
            }

            res.end(JSON.stringify({ days, created_date, registrar }));
          } catch (error) {
            console.error('[Vite] WHOIS Error:', error);
            res.statusCode = 500;
            res.end(JSON.stringify({ error: 'Failed to fetch domain age' }));
          }
          return;
        }
        next();
      });
    }
  };
}

export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080,
    hmr: {
      overlay: false,
    },
  },
  plugins: [
    whoisPlugin(),
    react(),
    mode === "development" && componentTagger(),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['robots.txt', 'pwa-512x512.png'],
      devOptions: {
        enabled: true
      },
      workbox: {
        maximumFileSizeToCacheInBytes: 5000000,
        cleanupOutdatedCaches: true,
      },
      manifest: {
        name: 'PhishGuard - AI Phishing Detection',
        short_name: 'PhishGuard',
        description: 'AI-powered phishing detection for URLs, emails, SMS, QR codes, and screenshots.',
        theme_color: '#0a1120',
        background_color: '#0a1120',
        display: 'standalone',
        orientation: 'portrait',
        scope: '/',
        start_url: '/',
        id: '/',
        lang: 'en',
        dir: 'ltr' as any,
        categories: ['security', 'utilities'],
        prefer_related_applications: false,
        display_override: ['standalone', 'window-controls-overlay'] as any,
        shortcuts: [
          {
            name: 'Scan URL',
            short_name: 'Scan',
            description: 'Open the phishing scanner',
            url: '/',
            icons: [{ src: 'pwa-512x512.png', sizes: '512x512', type: 'image/png' }]
          },
          {
            name: 'About PhishGuard',
            short_name: 'About',
            description: 'Learn about PhishGuard',
            url: '/about',
            icons: [{ src: 'pwa-512x512.png', sizes: '512x512', type: 'image/png' }]
          }
        ] as any,
        screenshots: [
          {
            src: 'screenshot-desktop.png',
            sizes: '1280x720',
            type: 'image/png',
            form_factor: 'wide',
            label: 'PhishGuard Desktop - AI Phishing Scanner'
          },
          {
            src: 'screenshot-mobile.png',
            sizes: '750x1334',
            type: 'image/png',
            form_factor: 'narrow',
            label: 'PhishGuard Mobile - Scan URLs on the go'
          }
        ] as any,
        icons: [
          {
            src: 'pwa-512x512.png',
            sizes: '192x192',
            type: 'image/png',
            purpose: 'any'
          },
          {
            src: 'pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'any'
          },
          {
            src: 'pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'maskable'
          }
        ]
      }
    })
  ].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}));
