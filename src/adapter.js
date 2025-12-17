"use strict";

const CloudflareChallenge = require("acme-dns-01-cloudflare");

module.exports = {
    create: function(opts) {
        // Instantiate the legacy v2/v3 library
        const legacy = new CloudflareChallenge({
            token: opts.token,
            verifyPropagation: true,
            verbose: false
        });

        return {
            // v4 API: init (no-op)
            init: async function() { return null; },

            // v4 API: set -> wraps legacy set
            set: function(data) {
                const domain = data.identifier.value;
                const challengeKey = data.challenge.dnsHost;
                const keyAuthorization = data.challenge.keyAuthorization;

                return new Promise((resolve, reject) => {
                    // Legacy signature: (opts, domain, key, val, cb)
                    legacy.set({}, domain, challengeKey, keyAuthorization, function(err) {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            },

            // v4 API: remove -> wraps legacy remove
            remove: function(data) {
                const domain = data.identifier.value;
                const challengeKey = data.challenge.dnsHost;

                return new Promise((resolve, reject) => {
                    // Legacy signature: (opts, domain, key, cb)
                    legacy.remove({}, domain, challengeKey, function(err) {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            },

            // v4 API: get (no-op)
            get: async function() { return null; }
        };
    }
};