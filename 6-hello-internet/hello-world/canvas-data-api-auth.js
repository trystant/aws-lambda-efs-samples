var crypto = require('crypto')
var url = require('url')
var HMAC_ALG = 'sha256'
var apiAuth = module.exports = {
    buildMessage: function(secret, timestamp, reqOpts) {
        var urlInfo = url.parse(reqOpts.path, true)
        var sortedParams = Object.keys(urlInfo.query).sort(function(a, b) {
            return a.localeCompare(b)
        })
        var sortedParts = []
        for (var i = 0; i < sortedParams.length; i++) {
            var paramName = sortedParams[i]
            sortedParts.push(paramName + '=' + urlInfo.query[paramName])
        }
        var parts = [
            reqOpts.method.toUpperCase(),
            reqOpts.host || '',
            reqOpts.contentType || '',
            reqOpts.contentMD5 || '',
            urlInfo.pathname,
            sortedParts.join('&') || '',
            timestamp,
            secret
        ]
        return parts.join('\n')
    },
    buildHmacSig: function(secret, timestamp, reqOpts) {
        var message = apiAuth.buildMessage(secret, timestamp, reqOpts)
        var hmac = crypto.createHmac(HMAC_ALG, new Buffer(secret))
        hmac.update(message)
        return hmac.digest('base64')
    }
}
