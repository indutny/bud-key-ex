var md5sha1 = require('md5-sha1');
var rsa = require('raw-rsa');
var ecdsa = require('raw-ecdsa');
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
    var json;
    var nginx = false;
    if (req.headers['content-type'] === 'application/json') {
      try {
        json = JSON.parse(chunks);
      } catch (e) {
        res.json(500, {
          error: e.stack || e
        });
        return;
      }

    // nginx request
    } else {
      nginx = true;
      json = {
        type: req.headers['x-type'],
        md: req.headers['x-md'],
        key: req.headers['x-key'],
        data: chunks
      };
    }

    self.handleJSON(sni, json, res, nginx);
  });
};

Server.prototype.handleJSON = function handleJSON(sni, json, res, nginx) {
  var key = this.sni[sni] && this.sni[sni][json.key || 'rsa'] ||
            this.key && this.key[json.key || 'rsa'];
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
    this.sign(key, json.key, json.md, data, done);
  else
    this.decrypt(key, data, done);

  function done(err, response) {
    if (err) {
      return res.json(500, {
        error: err.stack || err
      });
    }
    if (nginx) {
      res.writeHead(200);
      res.end(response.toString('base64'));
    } else {
      res.json(200, {
        response: response.toString('base64')
      });
    }
  }
};

Server.prototype.sign = function sign(key, type, md, data, cb) {
  var res;
  try {
    if (md === 'MD5-SHA1') {
      res = md5sha1.sign(data, key);
    } else if (type === 'rsa') {
      res = crypto.createSign(md).update(data).sign(key);
    } else if (type === 'ec') {
      var hash = crypto.createHash(md).update(data).digest();
      res = new ecdsa.Key(key).sign(hash);
    } else
      throw new Error('Unknown key type: ' + type);
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

Object.keys(Server.prototype).forEach(function(key) {
  SecureServer.prototype[key] = Server.prototype[key];
});
