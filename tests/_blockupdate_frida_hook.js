/*
 * frida hook: WinINet HTTPS 明文捕获
 *
 * 目标:还原 cloud_storage.dll 通过 WinINet 发往 cloud.10jqka.com.cn:443 的
 * HTTPS 请求/响应明文(请求行、头、请求体、响应状态/头/体)。
 *
 * 6 个 hook 点(对应交接文档 P0):
 *   InternetConnectA          -> 服务器/端口
 *   HttpOpenRequestA          -> verb / object path
 *   HttpAddRequestHeadersA    -> 请求头
 *   HttpSendRequestExA/W      -> 触发请求(开始事务)
 *   InternetWriteFile         -> POST/PUT 请求体
 *   InternetReadFile          -> 响应体(可多次调用)
 *   HttpQueryInfoA            -> 响应状态码/长度/Range
 *
 * 数据通过 send() 发回 Python 端,二进制用 base64。
 */

// 把 HINTERNET handle 映射到上下文(verb/path/连接host/已读响应)
var ctxByHandle = {};

// 读 ANSI 字符串,失败返回 null(而不是抛异常)
function safeCstr(p) {
  if (p.isNull()) return null;
  try { return p.readAnsiString(); } catch (e) { return null; }
}

// ── InternetConnectA: 记录 host:port ─────────────────────────
var pInternetConnectA = Module.findExportByName('wininet.dll', 'InternetConnectA');
if (pInternetConnectA) {
  Interceptor.attach(pInternetConnectA, {
    onEnter: function (args) {
      // HINTERNET hConnect, LPCSTR lpszServer, INTERNET_PORT nServerPort, ...
      var server = safeCstr(args[1]);
      var port = args[2].toInt32() & 0xffff;
      this.server = server; this.port = port;
    },
    onLeave: function (retval) {
      if (!retval.isNull()) {
        ctxByHandle[retval.toString()] = { kind: 'connect', server: this.server, port: this.port };
      }
      send({ t: 'connect', handle: retval.toString(), server: this.server, port: this.port });
    }
  });
  send({ t: 'note', msg: 'hooked InternetConnectA' });
} else { send({ t: 'note', msg: 'MISSING InternetConnectA' }); }

// ── HttpOpenRequestA: verb + object path ──────────────────────
var pHttpOpenRequestA = Module.findExportByName('wininet.dll', 'HttpOpenRequestA');
if (pHttpOpenRequestA) {
  Interceptor.attach(pHttpOpenRequestA, {
    onEnter: function (args) {
      // hConnect, verb, object name, version, referrer, accept*, flags, context
      this.hConnect = args[0].toString();
      this.verb = safeCstr(args[1]) || 'GET';
      this.obj = safeCstr(args[2]);
    },
    onLeave: function (retval) {
      var reqHandle = retval.toString();
      var conn = ctxByHandle[this.hConnect] || {};
      ctxByHandle[reqHandle] = {
        kind: 'request',
        connHandle: this.hConnect,
        server: conn.server, port: conn.port,
        verb: this.verb, obj: this.obj,
        headers: {}, reqBody: null, respChunks: [], respStatus: null
      };
      send({
        t: 'request',
        handle: reqHandle,
        connHandle: this.hConnect,
        server: conn.server, port: conn.port,
        verb: this.verb, obj: this.obj
      });
    }
  });
  send({ t: 'note', msg: 'hooked HttpOpenRequestA' });
} else { send({ t: 'note', msg: 'MISSING HttpOpenRequestA' }); }

// ── HttpAddRequestHeadersA: 请求头 ────────────────────────────
var pHttpAddRequestHeadersA = Module.findExportByName('wininet.dll', 'HttpAddRequestHeadersA');
if (pHttpAddRequestHeadersA) {
  Interceptor.attach(pHttpAddRequestHeadersA, {
    onEnter: function (args) {
      var h = args[0].toString();
      var hdrs = safeCstr(args[1]);
      var len = args[2].toInt32();
      // 多个 header 一次性传,按 \r\n 切
      send({ t: 'req_headers', handle: h, headers: hdrs });
      // 也存到 ctx
      var ctx = ctxByHandle[h];
      if (ctx && hdrs) {
        hdrs.split(/\r\n/).forEach(function (line) {
          var i = line.indexOf(':');
          if (i > 0) ctx.headers[line.slice(0,i).trim()] = line.slice(i+1).trim();
        });
      }
    }
  });
  send({ t: 'note', msg: 'hooked HttpAddRequestHeadersA' });
}

// ── HttpSendRequestExA / HttpSendRequestW: 标记请求发送 ───────
function hookSendRequest(name) {
  var p = Module.findExportByName('wininet.dll', name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) {
      this.h = args[0].toString();
    },
    onLeave: function (retval) {
      send({ t: 'send', handle: this.h, ok: !retval.isNull() });
    }
  });
  send({ t: 'note', msg: 'hooked ' + name });
}
hookSendRequest('HttpSendRequestExA');
hookSendRequest('HttpSendRequestW');
hookSendRequest('HttpSendRequestA');

// HTTP_QUERY_* 常量(低位) + HTTP_QUERY_FLAG_NUMBER(0x20000000) + HTTP_QUERY_FLAG_REQUEST_HEADERS(0x80000000)
// 参考 wininet.h。level = flags | index
var HTTP_QUERY_NAMES = {
  0: 'MIME_VERSION', 1: 'CONTENT_TYPE', 2: 'CONTENT_TRANSFER_ENCODING',
  3: 'CONTENT_ID', 4: 'CONTENT_DESCRIPTION', 5: 'CONTENT_LENGTH',
  6: 'CONTENT_LANGUAGE', 7: 'ALLOW', 8: 'EXPIRES', 9: 'LAST_MODIFIED',
  10: 'PRAGMA', 11: 'VERSION', 12: 'STATUS_CODE', 13: 'STATUS_TEXT',
  14: 'DATE', 15: 'CONNECTION', 19: 'MESSAGE_ID', 20: 'URI',
  21: 'ORIG_URI', 22: 'CONTENT_RANGE', 23: 'FROM', 24: 'HOST',
  25: 'LOCATION', 27: 'SERVER', 28: 'WWW_AUTHENTICATE', 29: 'ETAG',
  30: 'EXPECT', 31: 'RANGE', 32: 'ACCEPT_RANGES', 33: 'REFERER',
  34: 'ACCEPT', 35: 'ACCEPT_ENCODING', 36: 'ACCEPT_LANGUAGE',
  37: 'AUTHORIZATION', 38: 'COOKIE', 39: 'SET_COOKIE',
  41: 'ACCEPT_CHARSET', 42: 'USER_AGENT', 43: 'PROXY_AUTHENTICATE',
  44: 'PROXY_AUTHORIZATION', 45: 'AGE', 46: 'CACHE_CONTROL',
  47: 'CONTENT_ENCODING', 48: 'CONTENT_LOCATION', 49: 'CONTENT_MD5',
  50: 'CONTENT_SECURITY', 53: 'VIA', 55: 'KEEP_ALIVE',
};
function infoLevelName(level) {
  var flags = level & 0xffff0000;
  var idx = level & 0xffff;
  var name = HTTP_QUERY_NAMES[idx] || ('IDX_' + idx);
  var f = [];
  if (flags & 0x20000000) f.push('NUMBER');
  if (flags & 0x40000000) f.push('COALESCE');
  if (flags & 0x80000000) f.push('REQUEST_HEADERS');
  return name + (f.length ? ('|' + f.join('|')) : '');
}

// ── InternetWriteFile: POST/PUT 请求体 ────────────────────────
var pInternetWriteFile = Module.findExportByName('wininet.dll', 'InternetWriteFile');
if (pInternetWriteFile) {
  Interceptor.attach(pInternetWriteFile, {
    onEnter: function (args) {
      // HINTERNET, lpBuffer, dwNumberOfBytesToWrite, lpdw... NULL
      this.h = args[0].toString();
      this.buf = args[1];
      this.len = args[2].toInt32();
    },
    onLeave: function (retval) {
      if (this.len > 0) {
        // 用 send 的 data 附件传原始字节,避免 base64 经 JSON 被截断/吞掉
        try {
          var arr = this.buf.readByteArray(this.len);
          send({ t: 'req_body', handle: this.h, len: this.len }, arr);
        } catch (e) {
          send({ t: 'req_body_err', handle: this.h, err: e.toString() });
        }
      }
    }
  });
  send({ t: 'note', msg: 'hooked InternetWriteFile' });
}

// ── HttpQueryInfoA: 响应状态/长度/Range ───────────────────────
var pHttpQueryInfoA = Module.findExportByName('wininet.dll', 'HttpQueryInfoA');
if (pHttpQueryInfoA) {
  Interceptor.attach(pHttpQueryInfoA, {
    onEnter: function (args) {
      // HINTERNET, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex
      this.h = args[0].toString();
      this.infoLevel = args[1].toInt32() >>> 0;
      this.buf = args[2];
      this.pLen = args[3];
    },
    onLeave: function (retval) {
      try {
        var len = this.pLen.isNull() ? 0 : this.pLen.readU32();
        var value = null;
        var isNumber = (this.infoLevel & 0x20000000) !== 0;
        if (!this.buf.isNull() && len > 0) {
          if (isNumber && len >= 4) {
            value = String(this.buf.readU32() >>> 0);
          } else {
            // ANSI 字符串,len 含末尾 NUL
            try {
              value = this.buf.readUtf8String(len);
              if (value === null) value = this.buf.readAnsiString(len);
            } catch (e) {
              try { value = this.buf.readAnsiString(len); } catch (e2) {}
            }
          }
        }
        send({
          t: 'query_info',
          handle: this.h,
          infoLevel: infoLevelName(this.infoLevel),
          levelRaw: '0x' + this.infoLevel.toString(16),
          value: value,
          len: len
        });
      } catch (e) {
        send({ t: 'query_info_err', handle: this.h, err: e.toString() });
      }
    }
  });
  send({ t: 'note', msg: 'hooked HttpQueryInfoA' });
}

// ── InternetReadFile: 响应体(可能多次调用) ───────────────────
var pInternetReadFile = Module.findExportByName('wininet.dll', 'InternetReadFile');
if (pInternetReadFile) {
  Interceptor.attach(pInternetReadFile, {
    onEnter: function (args) {
      // HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdw...
      this.h = args[0].toString();
      this.buf = args[1];
      this.pBytesRead = args[3];
    },
    onLeave: function (retval) {
      try {
        var n = this.pBytesRead.isNull() ? 0 : this.pBytesRead.readU32();
        if (n > 0) {
          // 用 send 的 data 附件传原始字节,避免 base64 经 JSON 被吞
          var arr = this.buf.readByteArray(n);
          send({ t: 'resp_body', handle: this.h, len: n }, arr);
        }
      } catch (e) {
        send({ t: 'read_err', handle: this.h, err: e.toString() });
      }
    }
  });
  send({ t: 'note', msg: 'hooked InternetReadFile' });
}

send({ t: 'ready' });
