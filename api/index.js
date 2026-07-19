const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();
app.use(cors());
app.use(express.json());

async function scrapeOkestream() {
    try {
        console.log('🔍 Scraping Okestream...');
        
        const response = await axios.get('https://okestream.tv/', {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
                'Referer': 'https://okestream.tv/',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            },
            timeout: 20000
        });

        const html = response.data;
        const $ = cheerio.load(html);
        
        const matches = [];
        
        // ===== SELECTOR BARU YANG LEBIH FLEKSIBEL =====
        
        // 1. Cari semua div yang punya class mengandung 'match', 'live', 'event'
        $('div[class*="match"], div[class*="live"], div[class*="event"], div[class*="game"], div[class*="fixture"]').each((i, el) => {
            const text = $(el).text();
            
            // Cari nama tim (pola "Tim A vs Tim B")
            const vsMatch = text.match(/([A-Za-z\s]+)\s+vs\s+([A-Za-z\s]+)/i);
            const title = vsMatch ? `${vsMatch[1].trim()} vs ${vsMatch[2].trim()}` : null;
            
            // Cari liga
            const leagueMatch = text.match(/(Liga|Premier|La Liga|Serie|Bundesliga|Ligue|Champions|Europa|Indonesia|Pers|PS|Arema|Bali|Borneo|PSS|Barito|Madura|Dewa|Malut|Semen|PSIS|PSM|Persija|Persib|Persebaya)/i);
            const league = leagueMatch ? leagueMatch[0] : 'Liga Unknown';
            
            // Cari link m3u8 di sekitar elemen
            const parentHtml = $(el).closest('div, section, article').html() || '';
            const m3u8Match = parentHtml.match(/https?:\/\/[^\s"\']+\.m3u8/);
            const m3u8Link = m3u8Match ? m3u8Match[0] : null;
            
            // Cari iframe
            const iframe = $(el).find('iframe').attr('src') || 
                          $(el).closest('div, section, article').find('iframe').attr('src');
            
            if (title || m3u8Link || iframe) {
                matches.push({
                    id: `match-${Date.now()}-${i}`,
                    title: title || `Match ${i+1}`,
                    league: league,
                    time: 'LIVE',
                    streamLink: iframe || null,
                    m3u8Link: m3u8Link || null,
                    thumbnail: null,
                    isLive: true
                });
            }
        });

        // 2. Kalo masih kosong, cari semua iframe
        if (matches.length === 0) {
            console.log('⚠️ Selector pertama kosong, cari iframe...');
            
            $('iframe').each((i, el) => {
                const src = $(el).attr('src');
                if (src && (src.includes('m3u8') || src.includes('stream') || src.includes('live'))) {
                    const parentText = $(el).closest('div, section, article').text().trim();
                    const vsMatch = parentText.match(/([A-Za-z\s]+)\s+vs\s+([A-Za-z\s]+)/i);
                    
                    matches.push({
                        id: `iframe-${i}-${Date.now()}`,
                        title: vsMatch ? `${vsMatch[1].trim()} vs ${vsMatch[2].trim()}` : `Match ${i+1}`,
                        league: 'Liga Unknown',
                        time: 'LIVE',
                        streamLink: src,
                        m3u8Link: src.includes('.m3u8') ? src : null,
                        thumbnail: null,
                        isLive: true
                    });
                }
            });
        }

        // 3. Kalo masih kosong, cari semua link yang mengandung stream
        if (matches.length === 0) {
            console.log('⚠️ Iframe kosong, cari link stream...');
            
            $('a[href*="m3u8"], a[href*="stream"], a[href*="live"]').each((i, el) => {
                const href = $(el).attr('href');
                const text = $(el).text().trim() || $(el).closest('div, section, article').text().trim();
                const vsMatch = text.match(/([A-Za-z\s]+)\s+vs\s+([A-Za-z\s]+)/i);
                
                matches.push({
                    id: `link-${i}-${Date.now()}`,
                    title: vsMatch ? `${vsMatch[1].trim()} vs ${vsMatch[2].trim()}` : `Match ${i+1}`,
                    league: 'Liga Unknown',
                    time: 'LIVE',
                    streamLink: href,
                    m3u8Link: href.includes('.m3u8') ? href : null,
                    thumbnail: null,
                    isLive: true
                });
            });
        }

        console.log(`✅ Dapet ${matches.length} pertandingan`);
        
        // Kalo tetep 0, kasih dummy biar web gak kosong
        if (matches.length === 0) {
            return getDummyMatches();
        }
        
        return matches;

    } catch (error) {
        console.error('❌ Error scraping:', error.message);
        return getDummyMatches();
    }
}

// ===== DUMMY DATA (biar web gak kosong) =====
function getDummyMatches() {
    return [
        {
            id: 'dummy-1',
            title: 'Persib vs Persija (DUMMY)',
            league: 'Liga 1 Indonesia',
            time: 'LIVE',
            streamLink: null,
            m3u8Link: 'https://bfff1.hystreamer.com/live/5006838_F5hd01.m3u8',
            thumbnail: null,
            isLive: true
        },
        {
            id: 'dummy-2',
            title: 'Real Madrid vs Barcelona (DUMMY)',
            league: 'La Liga',
            time: 'LIVE',
            streamLink: null,
            m3u8Link: 'https://bfff1.hystreamer.com/live/5006838_F5hd01.m3u8',
            thumbnail: null,
            isLive: true
        },
        {
            id: 'dummy-3',
            title: 'Manchester City vs Liverpool (DUMMY)',
            league: 'Premier League',
            time: 'LIVE',
            streamLink: null,
            m3u8Link: 'https://bfff1.hystreamer.com/live/5006838_F5hd01.m3u8',
            thumbnail: null,
            isLive: true
        }
    ];
}

// ===== API ENDPOINTS =====
app.get('/api/matches', async (req, res) => {
    try {
        const matches = await scrapeOkestream();
        res.json({
            success: true,
            count: matches.length,
            matches: matches,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            matches: getDummyMatches()
        });
    }
});

app.get('/api/match/:id', async (req, res) => {
    try {
        const matches = await scrapeOkestream();
        const match = matches.find(m => m.id === req.params.id);
        
        if (match) {
            res.json({ success: true, match });
        } else {
            res.status(404).json({ success: false, error: 'Match not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = app;
