const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();
app.use(cors());
app.use(express.json());

// ===== FUNGSI SCRAPE OKESTREAM =====
async function scrapeOkestream() {
    try {
        console.log('🔍 Scraping Okestream...');
        
        const response = await axios.get('https://okestream.tv/', {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Referer': 'https://okestream.tv/'
            },
            timeout: 15000
        });

        const html = response.data;
        const $ = cheerio.load(html);
        
        const matches = [];
        
        // Cari elemen pertandingan (biasanya di class .live-match atau .match-item)
        $('.match-item, .live-match, .event, .match-row, .schedule-item').each((i, el) => {
            const title = $(el).find('.title, .match-name, .event-name, .team-name').text().trim();
            const league = $(el).find('.league, .tournament, .competition').text().trim();
            const time = $(el).find('.time, .match-time, .schedule-time').text().trim();
            
            // Cari link streaming (iframe atau direct link)
            let streamLink = $(el).find('iframe').attr('src');
            if (!streamLink) {
                streamLink = $(el).find('a[href*="m3u8"], a[href*="stream"], a[href*="live"]').attr('href');
            }
            if (!streamLink) {
                // Cari di parent atau sibling
                streamLink = $(el).closest('.match-container').find('iframe').attr('src');
            }
            
            // Cari link m3u8 dari atribut atau script
            let m3u8Link = null;
            const scriptContent = $(el).closest('.match-container').find('script').html();
            if (scriptContent) {
                const match = scriptContent.match(/https?:\/\/[^\s"\']+\.m3u8/);
                if (match) m3u8Link = match[0];
            }
            
            if (title || league || streamLink) {
                matches.push({
                    id: `match-${Date.now()}-${i}`,
                    title: title || 'Pertandingan Tanpa Nama',
                    league: league || 'Liga Unknown',
                    time: time || 'Waktu Tidak Tersedia',
                    streamLink: streamLink || null,
                    m3u8Link: m3u8Link || null,
                    thumbnail: $(el).find('img').attr('src') || null,
                    isLive: $(el).find('.live-badge, .badge-live').length > 0 || time.includes('LIVE')
                });
            }
        });

        // Kalo ga dapet pake selector di atas, coba cara alternatif
        if (matches.length === 0) {
            console.log('⚠️ Selector default ga dapet, coba alternatif...');
            
            // Cari semua iframe yang ada
            $('iframe').each((i, el) => {
                const src = $(el).attr('src');
                if (src && src.includes('m3u8') || src.includes('stream') || src.includes('live')) {
                    // Cari judul di sekitar iframe
                    const parentText = $(el).closest('div, section, article').text().trim();
                    const titleMatch = parentText.match(/([A-Za-z\s]+)\s+vs\s+([A-Za-z\s]+)/);
                    
                    matches.push({
                        id: `iframe-${i}-${Date.now()}`,
                        title: titleMatch ? `${titleMatch[1]} vs ${titleMatch[2]}` : `Match ${i+1}`,
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

        console.log(`✅ Dapet ${matches.length} pertandingan`);
        return matches;

    } catch (error) {
        console.error('❌ Error scraping:', error.message);
        // Fallback: kasih data dummy kalo error
        return getDummyMatches();
    }
}

// ===== DUMMY DATA (Fallback) =====
function getDummyMatches() {
    return [
        {
            id: 'dummy-1',
            title: 'Persib vs Persija',
            league: 'Liga 1 Indonesia',
            time: 'LIVE',
            streamLink: null,
            m3u8Link: 'https://bfff1.hystreamer.com/live/5006838_F5hd01.m3u8',
            thumbnail: null,
            isLive: true
        },
        {
            id: 'dummy-2',
            title: 'Real Madrid vs Barcelona',
            league: 'La Liga',
            time: 'LIVE',
            streamLink: null,
            m3u8Link: 'https://bfff1.hystreamer.com/live/5006838_F5hd01.m3u8',
            thumbnail: null,
            isLive: true
        }
    ];
}

// ===== API ENDPOINTS =====

// GET semua pertandingan
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

// GET satu pertandingan berdasarkan ID
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

// GET stream link langsung (pake header)
app.get('/api/stream/:id', async (req, res) => {
    try {
        const matches = await scrapeOkestream();
        const match = matches.find(m => m.id === req.params.id);
        
        if (match && match.m3u8Link) {
            // Proxy stream (biar tembus CORS)
            const streamUrl = match.m3u8Link;
            const response = await axios.get(streamUrl, {
                headers: {
                    'Referer': 'https://okestream.tv/',
                    'User-Agent': 'Mozilla/5.0'
                },
                responseType: 'stream'
            });
            
            res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
            response.data.pipe(res);
        } else {
            res.status(404).json({ success: false, error: 'Stream not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = app;
