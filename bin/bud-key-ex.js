#!/usr/bin/env node
var fs = require('fs');
var keyEx = require('../');
var cluster = require('cluster');

var config = JSON.parse(fs.readFileSync(process.argv[2]) + '');

if (config.secure) {
  config.secure.key = fs.readFileSync(config.secure.key);
  config.secure.cert = fs.readFileSync(config.secure.cert);
}

config.workers = config.workers || 1;

// Load keys
config.sni = config.sni || {};
Object.keys(config.sni).forEach(function(name) {
  this[name] = fs.readFileSync(this[name]);
}, config.sni);

config.key = config.key && fs.readFileSync(config.key);

config.port = config.port || 9000;
config.prefix = config.prefix || '/bud/key-ex/';

if (cluster.isMaster) {
  for (var i = 0; i < config.workers; i++) {
    fork();
    function fork() {
      cluster.fork().once('exit', fork);
    }
  }
  return;
}

keyEx.createServer(config).listen(config.port, config.host, function() {
  var addr = this.address();
  console.log('Listening on [%s]:%d', addr.address, addr.port);
});
