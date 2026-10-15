const { copyFileSync } = require('fs');
const path = require('path');

copyFileSync(path.join(__dirname, '..', '..', 'tests', 'fixtures', 'lab-src-app.js'), path.join(__dirname, '..', 'src', 'app.js'));
console.log('Restored the vulnerable lab source. This file is for local scanner testing only.');
