const fs = require('node:fs'); // file system tools
const path = require('node:path'); // path tools

const LOG_DIR = path.join(process.cwd(), 'logs'); // logs folder
const LOG_FILE = path.join(LOG_DIR, 'security.log'); // log file

if (!fs.existsSync(LOG_DIR)) { // if logs folder does not exist
  fs.mkdirSync(LOG_DIR, { recursive: true }); // create it
}

const eventHistory = new Map();

const THRESHOLD = 3;
const WINDOW_MS = 5 * 60 * 1000;

const writeSecurityLog = ({ event, ip, method, route, details = [] }) => { // log security event
  const logEntry = JSON.stringify({
    timestamp: new Date().toISOString(), // time of event
    event, // event type
    ip, // user IP
    method, // request method
    route, // request route
    details, // extra details
  }) + '\n'; // new line for each log

  fs.appendFile(LOG_FILE, logEntry, (err) => { // add log to file
    if (err) { // if error happens
      console.error('[SECURITY LOGGER] Failed to write log:', err.message); // show error
    }
  });
};

const monitorSecurityEvent = ({ event, ip }) => {
    if (!ip) return;

    const monitoredEvents = [
        'INVALID_TOKEN_USAGE',
        'AUTHENTICATION_FAILURE',
    ];

    if (!monitoredEvents.includes(event)) {
        return;
    }

    const now = Date.now();

    if (!eventHistory.has(ip)) {
        eventHistory.set(ip, []);
    }

    const events = eventHistory.get(ip);

    const recentEvents = events.filter(
        timestamp => now - timestamp < WINDOW_MS
    );

    recentEvents.push(now);
    eventHistory.set(ip, recentEvents);

    if (recentEvents.length >= THRESHOLD) {
        writeSecurityLog({
            event: 'SUSPICIOUS_ACTIVITY',
            ip,
            details: [
                `${recentEvents.length} ${event} events within 5 minutes`,
            ],
        });

        eventHistory.set(ip, []);
    }
};

const logSecurityEvent = ({
    event,
    ip,
    method,
    route,
    details = [],
}) => {
    // Write the original event
    writeSecurityLog({
        event,
        ip,
        method,
        route,
        details,
    });

    // Monitor it for suspicious repeated activity
    monitorSecurityEvent({
        event,
        ip,
    });
};

module.exports = { logSecurityEvent }; // export function