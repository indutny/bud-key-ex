var md5sha1 = require('md5-sha1');
var rsa = require('raw-rsa');
var crypto = require('crypto');
var constants = require('constants');

var Buffer = require('buffer').Buffer;
var http = require('http');
var https = require('https');
var util = require('util');

function Server(options) {
  http.Server.call(this, this.handleRequest);

  this.options = options;
  this.sni = options.sni;
  this.key = options.key;
}
util.inherits(Server, http.Server);
exports.Server = Server;

exports.createServer = function createServer(options) {
  if (options.secure)
    return new SecureServer(options);
  else
    return new Server(options);
};

function SecureServer(options) {
  https.Server.call(this, options.secure, this.handleRequest);

  this.options = options;
  this.sni = options.sni;
  this.key = options.key;
}
util.inherits(SecureServer, https.Server);
exports.SecureServer = SecureServer;

Server.prototype.handleRequest = function handleRequest(req, res) {
  res.json = function json(code, out) {
    var j = JSON.stringify(out);
    res.writeHead(code, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(j)
    });
    res.end(j);
  };

  if (req.url.indexOf(this.options.prefix) !== 0) {
    return res.json(404, {
      error: 'route not found'
    });
  }

  var sni = req.url.slice(this.options.prefix.length);

  var self = this;
  var chunks = '';
  req.on('data', function(chunk) {
    chunks += chunk;
  });
  req.once('end', function() {
    try {
      var json = JSON.parse(chunks);
    } catch (e) {
      res.json(500, {
        error: e.stack || e
      });
      return;
    }

    self.handleJSON(sni, json, res);
  });
};

Server.prototype.handleJSON = function handleJSON(sni, json, res) {
  var key = this.sni[sni] || this.key;
  if (!key) {
    return res.json(404, {
      error: 'No key found, matching: ' + sni
    });
  }

  try {
    var data = new Buffer(json.data, 'base64');
  } catch (e) {
    return res.json(500, {
      error: 'base64 parse failed'
    });
  }

  if (json.type === 'sign')
    this.sign(key, json.md, data, done);
  else
    this.decrypt(key, data, done);

  function done(err, response) {
    if (err) {
      return res.json(500, {
        error: err.stack || err
      });
    }
    res.json(200, {
      response: response.toString('base64')
    });
  }
};

Server.prototype.sign = function sign(key, md, data, cb) {
  var res;
  try {
    if (md === 'MD5-SHA1')
      res = md5sha1.sign(data, key);
    else
      res = crypto.createSign(md).update(data).sign(key);
  } catch (e) {
    cb(e);
    return;
  }

  cb(null, res);
};

Server.prototype.decrypt = function decrypt(key, data, cb) {
  var res;
  try {
    res = crypto.privateDecrypt({
      key: key,
      padding: constants.RSA_PKCS1_PADDING
    }, data);
  } catch (e) {
    cb(e);
    return;
  }

  cb(null, res);
};
