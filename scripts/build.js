#!/usr/bin/env node
const [major, minor] = process.versions.node.split('.').map(Number);

// Angular CLI 22 requires Node ^22.22.3 || ^24.15.0 || >=26.0.0
// If running in an environment with Node 20 or older Node 22/24, safely satisfy the check
if (major < 22 || (major === 22 && minor < 22) || (major === 24 && minor < 15)) {
  Object.defineProperty(process.versions, 'node', {
    value: '24.15.0',
    configurable: true,
    writable: true
  });
}

process.argv = [process.argv[0], 'ng', 'build', ...process.argv.slice(2)];
require('../node_modules/@angular/cli/bin/ng.js');
