'use strict';

var me = module.exports;

var crypto = require('crypto');

var libs = require('node-mod-load').libs;

var _sessionStorage = {};


var _newSession 
= me.newSession = function f_session_startSession($requestState) {
    
    var sid = $requestState.COOKIE.getCookie('SHPSSID');
    if (typeof _sessionStorage[sid] === 'undefined') {
        
        var s = new Session($requestState);
        sid = s.toString();
        _sessionStorage[sid] = s;
    }
    else {
        
        // ASVS 3.7 & 3.8 constantly rotating SID
        if (!$requestState._session_is_renewed) {
            
            var sssid = _sessionStorage[sid];
            delete _sessionStorage[sssid.toString()];
            sssid.updateRS($requestState);
            sid = sssid.genNewSID();
            _sessionStorage[sid] = sssid;
            $requestState._session_is_renewed = true;
        }
    }

    $requestState.COOKIE.setCookie('SHPSSID', sid, $requestState.config.securityConfig.sessionTimeout.value, true, libs.SFFM.isHTTPS($requestState.request));
    return _sessionStorage[sid];
};

var _closeSession 
= me.closeSession = function f_session_closeSession($sid) {

    if (typeof _sessionStorage[$sid] !== 'undefined') {

        delete _sessionStorage[$sid];
    }
};

var Session = function c_Session($requestState) {
    
    var _sid = $requestState.COOKIE.getCookie('SHPSSID');
    
    this.data = {};
    
    /**
     * Generate SID using
     * - IP
     * - 2048 char. long random string
     * - Date
     * hashed via SHA1
     * output as base64 string (35 char. long)
     * Inspired by PHP 5.6's SID generator
     * ASVS 3.11
     * 
     * @result string
     */
    this.genNewSID = function f_session_session_genNewSID() {

        var _sha1 = crypto.createHash('sha1');
        _sha1.update(libs.SFFM.getIP($requestState.request), 'ascii');
        _sha1.update(libs.SFFM.randomString(2048), 'ascii');
        _sha1.update((new Date).toISOString(), 'ascii');
        _sid = _sha1.digest('base64');

        return _sid;
    };

    this.updateRS = function f_session_session_updateRS($rs) {

        $requestState = $rs;
    };
    
    this.toString = function f_session_session_toString() {

        return _sid;
    };


    // CONSTRUCTOR
    // ASVS 3.14
    $requestState.COOKIE.setCookie('SHPSSID', this.genNewSID(), $requestState.config.securityConfig.sessionTimeout.value, true);
};
