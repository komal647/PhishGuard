

async function check(domain) {
    let days = 0;
    let created_date = 'Unknown';
    let registrar = 'Unknown';

    try {
      const rdapRes = await fetch(`https://rdap.org/domain/${domain}`);
      if (rdapRes.ok) {
        const rdapData = await rdapRes.json();
        
        // Parse Registration Event
        if (rdapData.events && Array.isArray(rdapData.events)) {
          console.log(`Events for ${domain}:`, JSON.stringify(rdapData.events, null, 2));
          const regEvent = rdapData.events.find(e => e.eventAction === 'registration');
          if (regEvent && regEvent.eventDate) {
            const firstSeen = new Date(regEvent.eventDate);
            days = Math.floor((Date.now() - firstSeen.getTime()) / (1000 * 60 * 60 * 24));
            created_date = regEvent.eventDate.substring(0, 10);
            console.log(`RDAP Success for ${domain}: ${days} days, ${created_date}`);
          }
        } else {
            console.log(`No events array in RDAP for ${domain}`);
        }
      } else {
        console.log(`RDAP failed for ${domain}: ${rdapRes.status}`);
      }
    } catch (e) {
      console.log(`RDAP error for ${domain}:`, e.message);
    }
}

async function run() {
    await check('google.com');
    await check('facebook.com');
    await check('qiscet.edu.in');
}

run();
