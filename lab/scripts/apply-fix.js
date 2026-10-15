const { copyFileSync } = require('fs');
const path = require('path');

copyFileSync(path.join(__dirname, '..', 'fixed', 'app.js'), path.join(__dirname, '..', 'src', 'app.js'));
console.log('Applied the fixed lab source. Re-run validation against lab/src.');
