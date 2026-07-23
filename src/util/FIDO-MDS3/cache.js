const fs = require('fs').promises;
const config = require('./config');

const memoryCache = { data: null, nonFidoData: null, nextUpdate: 0 };

async function saveToDisk(rawBlob, payloadMap, nextUpdate) {
  memoryCache.data = payloadMap;
  memoryCache.nextUpdate = new Date(nextUpdate).getTime();

  const cacheDataString = JSON.stringify(memoryCache.data, null, 3);
  await fs.writeFile(config.paths.cacheJson, cacheDataString, 'utf8');
  await fs.writeFile(config.paths.blob, rawBlob, 'utf8');
}

async function loadNonFidoMDS() {
  try {
    const rawData = await fs.readFile(config.paths.cacheNonFidoMDS, 'utf8');
    memoryCache.nonFidoData = JSON.parse(rawData);
    console.log("Loaded static non-FIDO MDS data.");
  } catch (err) {
    console.warn("Could not load cache-non-fido-mds.json. Proceeding without custom entries.", err.message);
    memoryCache.nonFidoData = {};
  }
}

async function loadFromDisk() {
  try {
    const rawBlob = await fs.readFile(config.paths.blob, 'utf8');
    return rawBlob; 
  } catch (err) {
    return null;
  }
}

module.exports = {
  memoryCache,
  saveToDisk,
  loadFromDisk,
  loadNonFidoMDS 
};