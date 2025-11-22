/**
 * Node-RED node for YARA Cryptex dictionary search
 */

module.exports = function(RED) {
    "use strict";

    function CryptexSearchNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        
        const axios = require('axios');
        const apiBase = config.apiBase || 'http://localhost:3005/api/v2/yara/cryptex';

        node.on('input', function(msg) {
            const query = config.query || msg.payload || msg.query;

            if (!query) {
                node.error('No search query provided');
                return;
            }

            const url = `${apiBase}/search?query=${encodeURIComponent(query)}`;

            axios.get(url)
                .then(response => {
                    msg.payload = response.data;
                    msg.cryptexResults = response.data;
                    msg.resultCount = response.data.length;
                    node.send(msg);
                })
                .catch(error => {
                    node.error('Cryptex search failed: ' + error.message);
                    msg.error = error.message;
                    node.send(msg);
                });
        });
    }

    RED.nodes.registerType("cryptex-search", CryptexSearchNode);
};

