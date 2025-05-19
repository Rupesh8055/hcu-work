const express = require('express');
const GeoIp = require('@maxmind/geoip2-node').Reader;
const path = require('path');
const app = express();
const port = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

GeoIp.open('./GeoLite2-City.mmdb').then(reader => {
  app.get('/ip-lookup', async (req, res) => {
    try {
      const ip = req.query.ip || req.ip;
      const response = await reader.city(ip);
      res.json({
        ip: ip,
        country: response.country.isoCode,
        city: response.city.names.en,
        latitude: response.location.latitude,
        longitude: response.location.longitude
      });
    } catch (error) {
      res.status(400).json({ error: 'Invalid IP or lookup failed' });
    }
  });

  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
});