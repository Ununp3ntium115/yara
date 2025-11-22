/**
 * Node-RED node for YARA Cryptex dictionary lookup
 */

module.exports = function(RED) {
    "use strict";

    function CryptexLookupNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        
        const axios = require('axios');
        const apiBase = config.apiBase || 'http://localhost:3005/api/v2/yara/cryptex';

        node.on('input', function(msg) {
            const lookupType = config.lookupType || msg.lookupType || 'symbol';
            const value = config.value || msg.payload || msg.symbol || msg.codename;

            if (!value) {
                node.error('No lookup value provided');
                return;
            }

            let url;
            if (lookupType === 'symbol') {
                url = `${apiBase}/lookup?symbol=${encodeURIComponent(value)}`;
            } else {
                url = `${apiBase}/lookup?pyro_name=${encodeURIComponent(value)}`;
            }

            axios.get(url)
                .then(response => {
                    if (response.data) {
                        msg.payload = response.data;
                        msg.cryptexEntry = response.data;
                        node.send(msg);
                    } else {
                        node.warn('Entry not found: ' + value);
                        msg.payload = null;
                        node.send(msg);
                    }
                })
                .catch(error => {
                    node.error('Cryptex lookup failed: ' + error.message);
                    msg.error = error.message;
                    node.send(msg);
                });
        });
    }

    RED.nodes.registerType("cryptex-lookup", CryptexLookupNode);
};

