/**
 * Node-RED node for YARA Cryptex dictionary statistics
 */

module.exports = function(RED) {
    "use strict";

    function CryptexStatsNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        
        const axios = require('axios');
        const apiBase = config.apiBase || 'http://localhost:3005/api/v2/yara/cryptex';

        node.on('input', function(msg) {
            const url = `${apiBase}/stats`;

            axios.get(url)
                .then(response => {
                    msg.payload = response.data;
                    msg.cryptexStats = response.data;
                    node.send(msg);
                })
                .catch(error => {
                    node.error('Cryptex stats failed: ' + error.message);
                    msg.error = error.message;
                    node.send(msg);
                });
        });
    }

    RED.nodes.registerType("cryptex-stats", CryptexStatsNode);
};

