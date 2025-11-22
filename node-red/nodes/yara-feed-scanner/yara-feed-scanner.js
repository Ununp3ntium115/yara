/**
 * Node-RED node for YARA feed scanning
 * Scans web feeds for latest YARA rules
 */

module.exports = function(RED) {
    "use strict";

    function YaraFeedScannerNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        
        const axios = require('axios');
        const apiBase = config.apiBase || 'http://localhost:3006/api/v2/yara/feed';

        node.on('input', function(msg) {
            const useCase = config.useCase || msg.useCase || 'all';
            const output = config.output || msg.output;

            let endpoint;
            switch(useCase) {
                case 'new_tasks':
                    endpoint = '/scan/new-tasks';
                    break;
                case 'old_tasks':
                    endpoint = '/scan/old-tasks';
                    break;
                case 'malware':
                    endpoint = '/scan/malware';
                    break;
                case 'apt':
                    endpoint = '/scan/apt';
                    break;
                case 'ransomware':
                    endpoint = '/scan/ransomware';
                    break;
                default:
                    endpoint = '/scan/all';
            }

            const url = `${apiBase}${endpoint}`;

            node.status({fill: "blue", shape: "dot", text: "scanning..."});

            axios.post(url, { output: output })
                .then(response => {
                    node.status({fill: "green", shape: "dot", text: "complete"});
                    msg.payload = response.data;
                    msg.rules = response.data.rules || [];
                    msg.ruleCount = response.data.ruleCount || 0;
                    node.send(msg);
                })
                .catch(error => {
                    node.status({fill: "red", shape: "dot", text: "error"});
                    node.error('YARA feed scan failed: ' + error.message);
                    msg.error = error.message;
                    node.send(msg);
                });
        });
    }

    RED.nodes.registerType("yara-feed-scanner", YaraFeedScannerNode);
};

