const path = require('path');

module.exports = {
  paths: {
    blob: path.join(__dirname, 'blob.jwt'),
    rootCert: path.join(__dirname, 'root-r3.crt'),
    cacheJson: path.join(__dirname, 'cache.json'),
    cacheNonFidoMDS: path.join(__dirname, 'cache-non-fido-mds.json'),
    errorLog: path.join(__dirname, 'mds-alerts.log')
  },
  urls: {
    fidoMds: 'https://mds.fidoalliance.org/',
    //fidoMds: 'http://localhost:8080/'
  },
  thresholds: {
    staleMs: 2 * 24 * 60 * 60 * 1000 
  }
};