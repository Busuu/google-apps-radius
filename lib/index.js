/*
 * Copyright (C) 2014 Tim Cooper
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

var dgram = require('dgram');

var _ = require('underscore');
var radius = require('radius');
var SMTPConnection = require('smtp-connection');

function now() {
    return new Date().toISOString() + ': ';
}

/**
 * Authenticates user log in information.
 *
 * `username` - the user (without @domain)
 * `password` - the password for the user
 * `domain` - the user's domain
 * `options` - extra options (optional)
 *      int `timeout` - milliseconds until timeout (default: 5000)
 *      bool `debug` - should debug messages be printed with console.log (default: false)
 * `callback` - callback with signature: callback(err, obj)
 *  object `obj`
 *      string `username` - the username
 *      string `domain`     - the domain of the user
 *      boolean `status`    - true if accepted, false otherwise
 */
var authenticate;

module.exports.authenticate = authenticate =
        function(username, password, options, callback) {
    if (!callback) {
        callback = options;
        options = {};
    }

    options = _.extend({
        timeout: 5000,
        debug: true,
    }, options);

    var conn = new SMTPConnection({
        port: 465,
        host: 'smtp.gmail.com',
        secure: true,
        requireTLS: true,
        connectionTimeout: options.timeout,
        socketTimeout: options.timeout,
        debug: options.debug,
    });

    conn.on('log', function(obj) {
        console.log(now() + ": " + obj.type + ": " + obj.message);
    });

    conn.on('error', function(err) {
        callback(err);
    });

    conn.connect(function() {
        var auth = {
            user: username,
            pass: password,
        };

        conn.login(auth, function(err) {
            if (err) {
                callback(err);
            } else {
                callback(null, {
                    username: username,
                    status: true,
                });
            }

            conn.quit();
        });
    });
}

/**
 * Creates a datagram socket that handles RADIUS Access-Request messages.
 *
 * object `options`
 *  string `domain`     - the Google apps domain name
 *  string `secret`     - the radius secret
 *  string `protocol` - "udp4" (default) or "udp6"
 *
 * The additional events can be emitted by the returned socket object:
 *
 * "radius" - when authentication of a user has completed. The following object
 * will be passed with the event:
 *
 *  object `obj`
 *      string `username` - the username
 *      string `domain`     - the domain of the user
 *      boolean `status`    - true if accepted, false otherwise
 *
 * "radius-error" - when an error occurs decoding or parsing the RADIUS
 * packet. The following object will be passed with the event:
 *
 *  object `obj`
 *      string `domain`  - the domain the RADIUS server is authenticating on
 *      string `message` - the error description
 */
module.exports.createServer = function (options) {
    // Defaults
    if (!options) {
        options = {};
    }
    if (!options.protocol) {
        options.protocol = 'udp4';
    }

    // Create server
    var server = dgram.createSocket(options.protocol);

    // Register callback
    server.on('message', function (msg, rinfo) {
        try {
            var packet = radius.decode({
                packet: msg,
                secret: options.secret
            });
        } catch (ex) {
            server.emit('radius-error', {
                message: ex.toString()
            });
            return;
        }

        if (packet.code != 'Access-Request') {
            server.emit('radius-error', {
                message: 'Packet code error: not "Access-Request"'
            });

            return;
        }

        var username = packet.attributes['User-Name'];
        var password = packet.attributes['User-Password'];

        console.log("Got Access-Request for " + username );

        // the username has to be an email address
        // using a simple custom email regex. Not the best solution. Should
        // use a library like isemail instead
        var emailRegExp = /[-a-zA-Z0-9.]+@([-a-zA-Z0-9]+\.)+([-0-9a-zA-Z]{2,})/;
        if (!username.match(emailRegExp)) {
            server.emit('radius-error', {
                message:'The username was not an email address'
            });

            var response = radius.encode_response({
                packet: packet,
                code: "Access-Reject",
                secret: options.secret
            });

            server.send(response, 0, response.length, rinfo.port, rinfo.address, function() {
                server.emit('radius', {
                    username: username,
                    status: false,
                });
            });

            return;
        }

        var acceptDomains = options.acceptDomains ? options.acceptDomains.split(',') : [];
        var domain = username.split('@')[1];

        if( acceptDomains.filter(function(d){ return d.indexOf(domain) >= 0; } ).length == 0 ){
            server.emit('radius-error', {
                message: 'Username '+username+' is not in an accepted domain. The complete list of allowed domains is '+acceptDomains.join(', ')
            });

            var response = radius.encode_response({
                packet: packet,
                code: "Access-Reject",
                secret: options.secret
            });

            server.send(response, 0, response.length, rinfo.port, rinfo.address, function() {
                server.emit('radius', {
                    username: username,
                    status: false,
                });
            });

            return;
        }

        // Reply function
        authenticate(username, password, options, function (err, obj) {
            var code = !err && obj.status ? 'Access-Accept' : 'Access-Reject';

            var response = radius.encode_response({
                packet: packet,
                code: code,
                secret: options.secret
            });

            server.send(response, 0, response.length, rinfo.port, rinfo.address, function() {
                if (err) {
                    obj = {
                        username: username,
                        status: false,
                    };
                }

                server.emit('radius', obj);
            });
        });
    });

    return server;
};
