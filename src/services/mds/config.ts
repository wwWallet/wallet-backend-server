import path from 'path';

const mdsDir = path.join(process.cwd(), 'src', 'services', 'mds');

export default {
  paths: {
    rootCert: path.join(mdsDir, 'root-r3.crt'),
    blob: path.join(mdsDir, 'blob.jwt'),
    cacheJson: path.join(mdsDir, 'cache.json'),
    errorLog: path.join(mdsDir, 'mds-alerts.log')
  },
  urls: {
    fidoMds: 'https://mds.fidoalliance.org/',
  },
  thresholds: {
    staleMs: 2 * 24 * 60 * 60 * 1000 
  }
};