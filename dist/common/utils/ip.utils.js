"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeIp = normalizeIp;
exports.extractClientIp = extractClientIp;
function normalizeIp(ip) {
    if (!ip) {
        return null;
    }
    let trimmed = ip.trim();
    if (trimmed.length === 0) {
        return null;
    }
    if (trimmed.startsWith('::ffff:')) {
        trimmed = trimmed.slice(7);
    }
    return trimmed.toLowerCase();
}
function extractClientIp(request) {
    var _a, _b, _c;
    const forwarded = request.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.length > 0) {
        const [first] = forwarded.split(',');
        const normalized = normalizeIp(first);
        if (normalized) {
            return normalized;
        }
    }
    const ip = (_c = (_a = request.ip) !== null && _a !== void 0 ? _a : (_b = request.socket) === null || _b === void 0 ? void 0 : _b.remoteAddress) !== null && _c !== void 0 ? _c : null;
    return normalizeIp(ip);
}
//# sourceMappingURL=ip.utils.js.map