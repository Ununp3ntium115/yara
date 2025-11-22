/**
 * YARA Cryptex - UI Interaction Logger
 * Client-side logging for all UI interactions
 * Injects into Svelte components to log clicks, inputs, navigation
 */

(function() {
    'use strict';
    
    const logEndpoint = '/api/v2/yara/cryptex/log';
    const sessionId = `ui_${Date.now()}`;
    const interactions = [];
    
    // Log to console and send to server
    function logInteraction(type, element, action, details = {}) {
        const interaction = {
            timestamp: new Date().toISOString(),
            sessionId: sessionId,
            type: type,
            element: element,
            action: action,
            details: details,
            url: window.location.href,
            userAgent: navigator.userAgent
        };
        
        interactions.push(interaction);
        console.log('[UI Logger]', interaction);
        
        // Send to server (if API available)
        try {
            fetch(logEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(interaction)
            }).catch(() => {
                // Silently fail if API not available
            });
        } catch (e) {
            // Silently fail
        }
    }
    
    // Intercept clicks
    document.addEventListener('click', function(e) {
        const element = e.target;
        const elementInfo = {
            tag: element.tagName,
            id: element.id,
            class: element.className,
            text: element.textContent?.substring(0, 100),
            selector: getSelector(element)
        };
        
        logInteraction('click', getElementName(element), 'clicked', elementInfo);
    }, true);
    
    // Intercept input
    document.addEventListener('input', function(e) {
        const element = e.target;
        if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
            logInteraction('input', getElementName(element), 'typed', {
                type: element.type,
                value: element.value?.substring(0, 100),
                selector: getSelector(element)
            });
        }
    }, true);
    
    // Intercept form submissions
    document.addEventListener('submit', function(e) {
        logInteraction('form', 'form', 'submitted', {
            action: e.target.action,
            method: e.target.method
        });
    }, true);
    
    // Log page navigation
    let lastUrl = location.href;
    new MutationObserver(() => {
        const url = location.href;
        if (url !== lastUrl) {
            lastUrl = url;
            logInteraction('navigation', 'page', 'navigated', {
                url: url,
                title: document.title
            });
        }
    }).observe(document, { subtree: true, childList: true });
    
    // Log errors
    window.addEventListener('error', function(e) {
        logInteraction('error', 'window', 'error', {
            message: e.message,
            filename: e.filename,
            lineno: e.lineno,
            colno: e.colno
        });
    });
    
    // Log console messages
    const originalLog = console.log;
    console.log = function(...args) {
        logInteraction('console', 'console', 'log', {
            message: args.join(' ')
        });
        originalLog.apply(console, args);
    };
    
    // Helper functions
    function getElementName(element) {
        if (element.id) return `#${element.id}`;
        if (element.className) return `.${element.className.split(' ')[0]}`;
        return element.tagName.toLowerCase();
    }
    
    function getSelector(element) {
        if (element.id) return `#${element.id}`;
        if (element.className) {
            const classes = element.className.split(' ').filter(c => c).map(c => `.${c}`).join('');
            return `${element.tagName.toLowerCase()}${classes}`;
        }
        return element.tagName.toLowerCase();
    }
    
    // Save interactions on page unload
    window.addEventListener('beforeunload', function() {
        localStorage.setItem(`ui_interactions_${sessionId}`, JSON.stringify(interactions));
    });
    
    // Log that logger is active
    console.log('[UI Logger] Active - All interactions will be logged');
    logInteraction('system', 'logger', 'initialized', {
        sessionId: sessionId,
        url: window.location.href
    });
})();

