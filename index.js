var demo = function() {
  "use strict";
  var encodeCache = {};
  // Create a lookup array where anything but characters in `chars` string
  // and alphanumeric chars is percent-encoded.
  
    function getEncodeCache(exclude) {
    var i, ch, cache = encodeCache[exclude];
    if (cache) {
      return cache;
    }
    cache = encodeCache[exclude] = [];
    for (i = 0; i < 128; i++) {
      ch = String.fromCharCode(i);
      if (/^[0-9a-z]$/i.test(ch)) {
        // always allow unencoded alphanumeric characters
        cache.push(ch);
      } else {
        cache.push("%" + ("0" + i.toString(16).toUpperCase()).slice(-2));
      }
    }
    for (i = 0; i < exclude.length; i++) {
      cache[exclude.charCodeAt(i)] = exclude[i];
    }
    return cache;
  }
  // Encode unsafe characters with percent-encoding, skipping already
  // encoded sequences.
  
  //  - string       - string to encode
  //  - exclude      - list of characters to ignore (in addition to a-zA-Z0-9)
  //  - keepEscaped  - don't encode '%' in a correct escape sequence (default: true)
  
    function encode(string, exclude, keepEscaped) {
    var i, l, code, nextCode, cache, result = "";
    if (typeof exclude !== "string") {
      // encode(string, keepEscaped)
      keepEscaped = exclude;
      exclude = encode.defaultChars;
    }
    if (typeof keepEscaped === "undefined") {
      keepEscaped = true;
    }
    cache = getEncodeCache(exclude);
    for (i = 0, l = string.length; i < l; i++) {
      code = string.charCodeAt(i);
      if (keepEscaped && code === 37 /* % */ && i + 2 < l) {
        if (/^[0-9a-f]{2}$/i.test(string.slice(i + 1, i + 3))) {
          result += string.slice(i, i + 3);
          i += 2;
          continue;
        }
      }
      if (code < 128) {
        result += cache[code];
        continue;
      }
      if (code >= 55296 && code <= 57343) {
        if (code >= 55296 && code <= 56319 && i + 1 < l) {
          nextCode = string.charCodeAt(i + 1);
          if (nextCode >= 56320 && nextCode <= 57343) {
            result += encodeURIComponent(string[i] + string[i + 1]);
            i++;
            continue;
          }
        }
        result += "%EF%BF%BD";
        continue;
      }
      result += encodeURIComponent(string[i]);
    }
    return result;
  }
  encode.defaultChars = ";/?:@&=+$,-_.!~*'()#";
  encode.componentChars = "-_.!~*'()";
  var encode_1 = encode;
  /* eslint-disable no-bitwise */  var decodeCache = {};
  function getDecodeCache(exclude) {
    var i, ch, cache = decodeCache[exclude];
    if (cache) {
      return cache;
    }
    cache = decodeCache[exclude] = [];
    for (i = 0; i < 128; i++) {
      ch = String.fromCharCode(i);
      cache.push(ch);
    }
    for (i = 0; i < exclude.length; i++) {
      ch = exclude.charCodeAt(i);
      cache[ch] = "%" + ("0" + ch.toString(16).toUpperCase()).slice(-2);
    }
    return cache;
  }
  // Decode percent-encoded string.
  
    function decode(string, exclude) {
    var cache;
    if (typeof exclude !== "string") {
      exclude = decode.defaultChars;
    }
    cache = getDecodeCache(exclude);
    return string.replace(/(%[a-f0-9]{2})+/gi, (function(seq) {
      var i, l, b1, b2, b3, b4, chr, result = "";
      for (i = 0, l = seq.length; i < l; i += 3) {
        b1 = parseInt(seq.slice(i + 1, i + 3), 16);
        if (b1 < 128) {
          result += cache[b1];
          continue;
        }
        if ((b1 & 224) === 192 && i + 3 < l) {
          // 110xxxxx 10xxxxxx
          b2 = parseInt(seq.slice(i + 4, i + 6), 16);
          if ((b2 & 192) === 128) {
            chr = b1 << 6 & 1984 | b2 & 63;
            if (chr < 128) {
              result += "\ufffd\ufffd";
            } else {
              result += String.fromCharCode(chr);
            }
            i += 3;
            continue;
          }
        }
        if ((b1 & 240) === 224 && i + 6 < l) {
          // 1110xxxx 10xxxxxx 10xxxxxx
          b2 = parseInt(seq.slice(i + 4, i + 6), 16);
          b3 = parseInt(seq.slice(i + 7, i + 9), 16);
          if ((b2 & 192) === 128 && (b3 & 192) === 128) {
            chr = b1 << 12 & 61440 | b2 << 6 & 4032 | b3 & 63;
            if (chr < 2048 || chr >= 55296 && chr <= 57343) {
              result += "\ufffd\ufffd\ufffd";
            } else {
              result += String.fromCharCode(chr);
            }
            i += 6;
            continue;
          }
        }
        if ((b1 & 248) === 240 && i + 9 < l) {
          // 111110xx 10xxxxxx 10xxxxxx 10xxxxxx
          b2 = parseInt(seq.slice(i + 4, i + 6), 16);
          b3 = parseInt(seq.slice(i + 7, i + 9), 16);
          b4 = parseInt(seq.slice(i + 10, i + 12), 16);
          if ((b2 & 192) === 128 && (b3 & 192) === 128 && (b4 & 192) === 128) {
            chr = b1 << 18 & 1835008 | b2 << 12 & 258048 | b3 << 6 & 4032 | b4 & 63;
            if (chr < 65536 || chr > 1114111) {
              result += "\ufffd\ufffd\ufffd\ufffd";
            } else {
              chr -= 65536;
              result += String.fromCharCode(55296 + (chr >> 10), 56320 + (chr & 1023));
            }
            i += 9;
            continue;
          }
        }
        result += "\ufffd";
      }
      return result;
    }));
  }
  decode.defaultChars = ";/?:@&=+$,#";
  decode.componentChars = "";
  var decode_1 = decode;
  var format = function format(url) {
    var result = "";
    result += url.protocol || "";
    result += url.slashes ? "//" : "";
    result += url.auth ? url.auth + "@" : "";
    if (url.hostname && url.hostname.indexOf(":") !== -1) {
      // ipv6 address
      result += "[" + url.hostname + "]";
    } else {
      result += url.hostname || "";
    }
    result += url.port ? ":" + url.port : "";
    result += url.pathname || "";
    result += url.search || "";
    result += url.hash || "";
    return result;
  };
  // Copyright Joyent, Inc. and other Node contributors.
  
  // Changes from joyent/node:
  
  // 1. No leading slash in paths,
  //    e.g. in `url.parse('http://foo?bar')` pathname is ``, not `/`
  
  // 2. Backslashes are not replaced with slashes,
  //    so `http:\\example.org\` is treated like a relative path
  
  // 3. Trailing colon is treated like a part of the path,
  //    i.e. in `http://example.org:foo` pathname is `:foo`
  
  // 4. Nothing is URL-encoded in the resulting object,
  //    (in joyent/node some chars in auth and paths are encoded)
  
  // 5. `url.parse()` does not have `parseQueryString` argument
  
  // 6. Removed extraneous result properties: `host`, `path`, `query`, etc.,
  //    which can be constructed using other parts of the url.
  
    function Url() {
    this.protocol = null;
    this.slashes = null;
    this.auth = null;
    this.port = null;
    this.hostname = null;
    this.hash = null;
    this.search = null;
    this.pathname = null;
  }
  // Reference: RFC 3986, RFC 1808, RFC 2396
  // define these here so at least they only have to be
  // compiled once on the first module load.
    var protocolPattern = /^([a-z0-9.+-]+:)/i, portPattern = /:[0-9]*$/, 
  // Special case for a simple path URL
  simplePathPattern = /^(\/\/?(?!\/)[^\?\s]*)(\?[^\s]*)?$/, 
  // RFC 2396: characters reserved for delimiting URLs.
  // We actually just auto-escape these.
  delims = [ "<", ">", '"', "`", " ", "\r", "\n", "\t" ], 
  // RFC 2396: characters not allowed for various reasons.
  unwise = [ "{", "}", "|", "\\", "^", "`" ].concat(delims), 
  // Allowed by RFCs, but cause of XSS attacks.  Always escape these.
  autoEscape = [ "'" ].concat(unwise), 
  // Characters that are never ever allowed in a hostname.
  // Note that any invalid chars are also handled, but these
  // are the ones that are *expected* to be seen, so we fast-path
  // them.
  nonHostChars = [ "%", "/", "?", ";", "#" ].concat(autoEscape), hostEndingChars = [ "/", "?", "#" ], hostnameMaxLen = 255, hostnamePartPattern = /^[+a-z0-9A-Z_-]{0,63}$/, hostnamePartStart = /^([+a-z0-9A-Z_-]{0,63})(.*)$/, 
  // protocols that can allow "unsafe" and "unwise" chars.
  /* eslint-disable no-script-url */
  // protocols that never have a hostname.
  hostlessProtocol = {
    javascript: true,
    "javascript:": true
  }, 
  // protocols that always contain a // bit.
  slashedProtocol = {
    http: true,
    https: true,
    ftp: true,
    gopher: true,
    file: true,
    "http:": true,
    "https:": true,
    "ftp:": true,
    "gopher:": true,
    "file:": true
  };
  /* eslint-enable no-script-url */  function urlParse(url, slashesDenoteHost) {
    if (url && url instanceof Url) {
      return url;
    }
    var u = new Url;
    u.parse(url, slashesDenoteHost);
    return u;
  }
  Url.prototype.parse = function(url, slashesDenoteHost) {
    var i, l, lowerProto, hec, slashes, rest = url;
    // trim before proceeding.
    // This is to support parse stuff like "  http://foo.com  \n"
        rest = rest.trim();
    if (!slashesDenoteHost && url.split("#").length === 1) {
      // Try fast path regexp
      var simplePath = simplePathPattern.exec(rest);
      if (simplePath) {
        this.pathname = simplePath[1];
        if (simplePath[2]) {
          this.search = simplePath[2];
        }
        return this;
      }
    }
    var proto = protocolPattern.exec(rest);
    if (proto) {
      proto = proto[0];
      lowerProto = proto.toLowerCase();
      this.protocol = proto;
      rest = rest.substr(proto.length);
    }
    // figure out if it's got a host
    // user@server is *always* interpreted as a hostname, and url
    // resolution will treat //foo/bar as host=foo,path=bar because that's
    // how the browser resolves relative URLs.
        if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
      slashes = rest.substr(0, 2) === "//";
      if (slashes && !(proto && hostlessProtocol[proto])) {
        rest = rest.substr(2);
        this.slashes = true;
      }
    }
    if (!hostlessProtocol[proto] && (slashes || proto && !slashedProtocol[proto])) {
      // there's a hostname.
      // the first instance of /, ?, ;, or # ends the host.
      // If there is an @ in the hostname, then non-host chars *are* allowed
      // to the left of the last @ sign, unless some host-ending character
      // comes *before* the @-sign.
      // URLs are obnoxious.
      // ex:
      // http://a@b@c/ => user:a@b host:c
      // http://a@b?@c => user:a host:c path:/?@c
      // v0.12 TODO(isaacs): This is not quite how Chrome does things.
      // Review our test case against browsers more comprehensively.
      // find the first instance of any hostEndingChars
      var hostEnd = -1;
      for (i = 0; i < hostEndingChars.length; i++) {
        hec = rest.indexOf(hostEndingChars[i]);
        if (hec !== -1 && (hostEnd === -1 || hec < hostEnd)) {
          hostEnd = hec;
        }
      }
      // at this point, either we have an explicit point where the
      // auth portion cannot go past, or the last @ char is the decider.
            var auth, atSign;
      if (hostEnd === -1) {
        // atSign can be anywhere.
        atSign = rest.lastIndexOf("@");
      } else {
        // atSign must be in auth portion.
        // http://a@b/c@d => host:b auth:a path:/c@d
        atSign = rest.lastIndexOf("@", hostEnd);
      }
      // Now we have a portion which is definitely the auth.
      // Pull that off.
            if (atSign !== -1) {
        auth = rest.slice(0, atSign);
        rest = rest.slice(atSign + 1);
        this.auth = auth;
      }
      // the host is the remaining to the left of the first non-host char
            hostEnd = -1;
      for (i = 0; i < nonHostChars.length; i++) {
        hec = rest.indexOf(nonHostChars[i]);
        if (hec !== -1 && (hostEnd === -1 || hec < hostEnd)) {
          hostEnd = hec;
        }
      }
      // if we still have not hit it, then the entire thing is a host.
            if (hostEnd === -1) {
        hostEnd = rest.length;
      }
      if (rest[hostEnd - 1] === ":") {
        hostEnd--;
      }
      var host = rest.slice(0, hostEnd);
      rest = rest.slice(hostEnd);
      // pull out port.
            this.parseHost(host);
      // we've indicated that there is a hostname,
      // so even if it's empty, it has to be present.
            this.hostname = this.hostname || "";
      // if hostname begins with [ and ends with ]
      // assume that it's an IPv6 address.
            var ipv6Hostname = this.hostname[0] === "[" && this.hostname[this.hostname.length - 1] === "]";
      // validate a little.
            if (!ipv6Hostname) {
        var hostparts = this.hostname.split(/\./);
        for (i = 0, l = hostparts.length; i < l; i++) {
          var part = hostparts[i];
          if (!part) {
            continue;
          }
          if (!part.match(hostnamePartPattern)) {
            var newpart = "";
            for (var j = 0, k = part.length; j < k; j++) {
              if (part.charCodeAt(j) > 127) {
                // we replace non-ASCII char with a temporary placeholder
                // we need this to make sure size of hostname is not
                // broken by replacing non-ASCII by nothing
                newpart += "x";
              } else {
                newpart += part[j];
              }
            }
            // we test again with ASCII char only
                        if (!newpart.match(hostnamePartPattern)) {
              var validParts = hostparts.slice(0, i);
              var notHost = hostparts.slice(i + 1);
              var bit = part.match(hostnamePartStart);
              if (bit) {
                validParts.push(bit[1]);
                notHost.unshift(bit[2]);
              }
              if (notHost.length) {
                rest = notHost.join(".") + rest;
              }
              this.hostname = validParts.join(".");
              break;
            }
          }
        }
      }
      if (this.hostname.length > hostnameMaxLen) {
        this.hostname = "";
      }
      // strip [ and ] from the hostname
      // the host field still retains them, though
            if (ipv6Hostname) {
        this.hostname = this.hostname.substr(1, this.hostname.length - 2);
      }
    }
    // chop off from the tail first.
        var hash = rest.indexOf("#");
    if (hash !== -1) {
      // got a fragment string.
      this.hash = rest.substr(hash);
      rest = rest.slice(0, hash);
    }
    var qm = rest.indexOf("?");
    if (qm !== -1) {
      this.search = rest.substr(qm);
      rest = rest.slice(0, qm);
    }
    if (rest) {
      this.pathname = rest;
    }
    if (slashedProtocol[lowerProto] && this.hostname && !this.pathname) {
      this.pathname = "";
    }
    return this;
  };
  Url.prototype.parseHost = function(host) {
    var port = portPattern.exec(host);
    if (port) {
      port = port[0];
      if (port !== ":") {
        this.port = port.substr(1);
      }
      host = host.substr(0, host.length - port.length);
    }
    if (host) {
      this.hostname = host;
    }
  };
  var parse = urlParse;
  var encode$1 = encode_1;
  var decode$1 = decode_1;
  var format$1 = format;
  var parse$1 = parse;
  var mdurl = {
    encode: encode$1,
    decode: decode$1,
    format: format$1,
    parse: parse$1
  };
  function deepFreeze(obj) {
    if (obj instanceof Map) {
      obj.clear = obj.delete = obj.set = function() {
        throw new Error("map is read-only");
      };
    } else if (obj instanceof Set) {
      obj.add = obj.clear = obj.delete = function() {
        throw new Error("set is read-only");
      };
    }
    // Freeze self
        Object.freeze(obj);
    Object.getOwnPropertyNames(obj).forEach((function(name) {
      var prop = obj[name];
      // Freeze prop if it is an object
            if (typeof prop == "object" && !Object.isFrozen(prop)) {
        deepFreeze(prop);
      }
    }));
    return obj;
  }
  var deepFreezeEs6 = deepFreeze;
  var _default = deepFreeze;
  deepFreezeEs6.default = _default;
  class Response {
    /**
     * @param {CompiledMode} mode
     */
    constructor(mode) {
      // eslint-disable-next-line no-undefined
      if (mode.data === undefined) mode.data = {};
      this.data = mode.data;
    }
    ignoreMatch() {
      this.ignore = true;
    }
  }
  /**
   * @param {string} value
   * @returns {string}
   */  function escapeHTML(value) {
    return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
  }
  /**
   * performs a shallow merge of multiple objects into one
   *
   * @template T
   * @param {T} original
   * @param {Record<string,any>[]} objects
   * @returns {T} a single new object
   */  function inherit(original, ...objects) {
    /** @type Record<string,any> */
    const result = Object.create(null);
    for (const key in original) {
      result[key] = original[key];
    }
    objects.forEach((function(obj) {
      for (const key in obj) {
        result[key] = obj[key];
      }
    }));
    /** @type {T} */
    return result;
  }
  /* Stream merging */
  /**
   * @typedef Event
   * @property {'start'|'stop'} event
   * @property {number} offset
   * @property {Node} node
   */
  /**
   * @param {Node} node
   */  function tag(node) {
    return node.nodeName.toLowerCase();
  }
  /**
   * @param {Node} node
   */  function nodeStream(node) {
    /** @type Event[] */
    const result = [];
    (function _nodeStream(node, offset) {
      for (let child = node.firstChild; child; child = child.nextSibling) {
        if (child.nodeType === 3) {
          offset += child.nodeValue.length;
        } else if (child.nodeType === 1) {
          result.push({
            event: "start",
            offset: offset,
            node: child
          });
          offset = _nodeStream(child, offset);
          // Prevent void elements from having an end tag that would actually
          // double them in the output. There are more void elements in HTML
          // but we list only those realistically expected in code display.
                    if (!tag(child).match(/br|hr|img|input/)) {
            result.push({
              event: "stop",
              offset: offset,
              node: child
            });
          }
        }
      }
      return offset;
    })(node, 0);
    return result;
  }
  /**
   * @param {any} original - the original stream
   * @param {any} highlighted - stream of the highlighted source
   * @param {string} value - the original source itself
   */  function mergeStreams(original, highlighted, value) {
    let processed = 0;
    let result = "";
    const nodeStack = [];
    function selectStream() {
      if (!original.length || !highlighted.length) {
        return original.length ? original : highlighted;
      }
      if (original[0].offset !== highlighted[0].offset) {
        return original[0].offset < highlighted[0].offset ? original : highlighted;
      }
      /*
      To avoid starting the stream just before it should stop the order is
      ensured that original always starts first and closes last:

      if (event1 == 'start' && event2 == 'start')
        return original;
      if (event1 == 'start' && event2 == 'stop')
        return highlighted;
      if (event1 == 'stop' && event2 == 'start')
        return original;
      if (event1 == 'stop' && event2 == 'stop')
        return highlighted;

      ... which is collapsed to:
      */      return highlighted[0].event === "start" ? original : highlighted;
    }
    /**
     * @param {Node} node
     */    function open(node) {
      /** @param {Attr} attr */
      function attributeString(attr) {
        return " " + attr.nodeName + '="' + escapeHTML(attr.value) + '"';
      }
      // @ts-ignore
            result += "<" + tag(node) + [].map.call(node.attributes, attributeString).join("") + ">";
    }
    /**
     * @param {Node} node
     */    function close(node) {
      result += "</" + tag(node) + ">";
    }
    /**
     * @param {Event} event
     */    function render(event) {
      (event.event === "start" ? open : close)(event.node);
    }
    while (original.length || highlighted.length) {
      let stream = selectStream();
      result += escapeHTML(value.substring(processed, stream[0].offset));
      processed = stream[0].offset;
      if (stream === original) {
        /*
        On any opening or closing tag of the original markup we first close
        the entire highlighted node stack, then render the original tag along
        with all the following original tags at the same offset and then
        reopen all the tags on the highlighted stack.
        */
        nodeStack.reverse().forEach(close);
        do {
          render(stream.splice(0, 1)[0]);
          stream = selectStream();
        } while (stream === original && stream.length && stream[0].offset === processed);
        nodeStack.reverse().forEach(open);
      } else {
        if (stream[0].event === "start") {
          nodeStack.push(stream[0].node);
        } else {
          nodeStack.pop();
        }
        render(stream.splice(0, 1)[0]);
      }
    }
    return result + escapeHTML(value.substr(processed));
  }
  var utils =  Object.freeze({
    __proto__: null,
    escapeHTML: escapeHTML,
    inherit: inherit,
    nodeStream: nodeStream,
    mergeStreams: mergeStreams
  });
  /**
   * @typedef {object} Renderer
   * @property {(text: string) => void} addText
   * @property {(node: Node) => void} openNode
   * @property {(node: Node) => void} closeNode
   * @property {() => string} value
   */
  /** @typedef {{kind?: string, sublanguage?: boolean}} Node */
  /** @typedef {{walk: (r: Renderer) => void}} Tree */
  /** */  const SPAN_CLOSE = "</span>";
  /**
   * Determines if a node needs to be wrapped in <span>
   *
   * @param {Node} node */  const emitsWrappingTags = node => !!node.kind;
  /** @type {Renderer} */  class HTMLRenderer {
    /**
     * Creates a new HTMLRenderer
     *
     * @param {Tree} parseTree - the parse tree (must support `walk` API)
     * @param {{classPrefix: string}} options
     */
    constructor(parseTree, options) {
      this.buffer = "";
      this.classPrefix = options.classPrefix;
      parseTree.walk(this);
    }
    /**
     * Adds texts to the output stream
     *
     * @param {string} text */    addText(text) {
      this.buffer += escapeHTML(text);
    }
    /**
     * Adds a node open to the output stream (if needed)
     *
     * @param {Node} node */    openNode(node) {
      if (!emitsWrappingTags(node)) return;
      let className = node.kind;
      if (!node.sublanguage) {
        className = `${this.classPrefix}${className}`;
      }
      this.span(className);
    }
    /**
     * Adds a node close to the output stream (if needed)
     *
     * @param {Node} node */    closeNode(node) {
      if (!emitsWrappingTags(node)) return;
      this.buffer += SPAN_CLOSE;
    }
    /**
     * returns the accumulated buffer
    */    value() {
      return this.buffer;
    }
    // helpers
    /**
     * Builds a span element
     *
     * @param {string} className */
    span(className) {
      this.buffer += `<span class="${className}">`;
    }
  }
  /** @typedef {{kind?: string, sublanguage?: boolean, children: Node[]} | string} Node */
  /** @typedef {{kind?: string, sublanguage?: boolean, children: Node[]} } DataNode */
  /**  */  class TokenTree {
    constructor() {
      /** @type DataNode */
      this.rootNode = {
        children: []
      };
      this.stack = [ this.rootNode ];
    }
    get top() {
      return this.stack[this.stack.length - 1];
    }
    get root() {
      return this.rootNode;
    }
    /** @param {Node} node */    add(node) {
      this.top.children.push(node);
    }
    /** @param {string} kind */    openNode(kind) {
      /** @type Node */
      const node = {
        kind: kind,
        children: []
      };
      this.add(node);
      this.stack.push(node);
    }
    closeNode() {
      if (this.stack.length > 1) {
        return this.stack.pop();
      }
      // eslint-disable-next-line no-undefined
            return undefined;
    }
    closeAllNodes() {
      while (this.closeNode()) ;
    }
    toJSON() {
      return JSON.stringify(this.rootNode, null, 4);
    }
    /**
     * @typedef { import("./html_renderer").Renderer } Renderer
     * @param {Renderer} builder
     */    walk(builder) {
      // this does not
      return this.constructor._walk(builder, this.rootNode);
      // this works
      // return TokenTree._walk(builder, this.rootNode);
        }
    /**
     * @param {Renderer} builder
     * @param {Node} node
     */    static _walk(builder, node) {
      if (typeof node === "string") {
        builder.addText(node);
      } else if (node.children) {
        builder.openNode(node);
        node.children.forEach((child => this._walk(builder, child)));
        builder.closeNode(node);
      }
      return builder;
    }
    /**
     * @param {Node} node
     */    static _collapse(node) {
      if (typeof node === "string") return;
      if (!node.children) return;
      if (node.children.every((el => typeof el === "string"))) {
        // node.text = node.children.join("");
        // delete node.children;
        node.children = [ node.children.join("") ];
      } else {
        node.children.forEach((child => {
          TokenTree._collapse(child);
        }));
      }
    }
  }
  /**
    Currently this is all private API, but this is the minimal API necessary
    that an Emitter must implement to fully support the parser.

    Minimal interface:

    - addKeyword(text, kind)
    - addText(text)
    - addSublanguage(emitter, subLanguageName)
    - finalize()
    - openNode(kind)
    - closeNode()
    - closeAllNodes()
    - toHTML()

  */
  /**
   * @implements {Emitter}
   */  class TokenTreeEmitter extends TokenTree {
    /**
     * @param {*} options
     */
    constructor(options) {
      super();
      this.options = options;
    }
    /**
     * @param {string} text
     * @param {string} kind
     */    addKeyword(text, kind) {
      if (text === "") {
        return;
      }
      this.openNode(kind);
      this.addText(text);
      this.closeNode();
    }
    /**
     * @param {string} text
     */    addText(text) {
      if (text === "") {
        return;
      }
      this.add(text);
    }
    /**
     * @param {Emitter & {root: DataNode}} emitter
     * @param {string} name
     */    addSublanguage(emitter, name) {
      /** @type DataNode */
      const node = emitter.root;
      node.kind = name;
      node.sublanguage = true;
      this.add(node);
    }
    toHTML() {
      const renderer = new HTMLRenderer(this, this.options);
      return renderer.value();
    }
    finalize() {
      return true;
    }
  }
  /**
   * @param {string} value
   * @returns {RegExp}
   * */  function escape(value) {
    return new RegExp(value.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&"), "m");
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat(...args) {
    const joined = args.map((x => source(x))).join("");
    return joined;
  }
  /**
   * @param {RegExp} re
   * @returns {number}
   */  function countMatchGroups(re) {
    return new RegExp(re.toString() + "|").exec("").length - 1;
  }
  /**
   * Does lexeme start with a regular expression match at the beginning
   * @param {RegExp} re
   * @param {string} lexeme
   */  function startsWith(re, lexeme) {
    const match = re && re.exec(lexeme);
    return match && match.index === 0;
  }
  // join logically computes regexps.join(separator), but fixes the
  // backreferences so they continue to match.
  // it also places each individual regular expression into it's own
  // match group, keeping track of the sequencing of those match groups
  // is currently an exercise for the caller. :-)
  /**
   * @param {(string | RegExp)[]} regexps
   * @param {string} separator
   * @returns {string}
   */  function join(regexps, separator = "|") {
    // backreferenceRe matches an open parenthesis or backreference. To avoid
    // an incorrect parse, it additionally matches the following:
    // - [...] elements, where the meaning of parentheses and escapes change
    // - other escape sequences, so we do not misparse escape sequences as
    //   interesting elements
    // - non-matching or lookahead parentheses, which do not capture. These
    //   follow the '(' with a '?'.
    const backreferenceRe = /\[(?:[^\\\]]|\\.)*\]|\(\??|\\([1-9][0-9]*)|\\./;
    let numCaptures = 0;
    let ret = "";
    for (let i = 0; i < regexps.length; i++) {
      numCaptures += 1;
      const offset = numCaptures;
      let re = source(regexps[i]);
      if (i > 0) {
        ret += separator;
      }
      ret += "(";
      while (re.length > 0) {
        const match = backreferenceRe.exec(re);
        if (match == null) {
          ret += re;
          break;
        }
        ret += re.substring(0, match.index);
        re = re.substring(match.index + match[0].length);
        if (match[0][0] === "\\" && match[1]) {
          // Adjust the backreference.
          ret += "\\" + String(Number(match[1]) + offset);
        } else {
          ret += match[0];
          if (match[0] === "(") {
            numCaptures++;
          }
        }
      }
      ret += ")";
    }
    return ret;
  }
  // Common regexps
    const IDENT_RE = "[a-zA-Z]\\w*";
  const UNDERSCORE_IDENT_RE = "[a-zA-Z_]\\w*";
  const NUMBER_RE = "\\b\\d+(\\.\\d+)?";
  const C_NUMBER_RE = "(-?)(\\b0[xX][a-fA-F0-9]+|(\\b\\d+(\\.\\d*)?|\\.\\d+)([eE][-+]?\\d+)?)";
 // 0x..., 0..., decimal, float
    const BINARY_NUMBER_RE = "\\b(0b[01]+)";
 // 0b...
    const RE_STARTERS_RE = "!|!=|!==|%|%=|&|&&|&=|\\*|\\*=|\\+|\\+=|,|-|-=|/=|/|:|;|<<|<<=|<=|<|===|==|=|>>>=|>>=|>=|>>>|>>|>|\\?|\\[|\\{|\\(|\\^|\\^=|\\||\\|=|\\|\\||~";
  /**
  * @param { Partial<Mode> & {binary?: string | RegExp} } opts
  */  const SHEBANG = (opts = {}) => {
    const beginShebang = /^#![ ]*\//;
    if (opts.binary) {
      opts.begin = concat(beginShebang, /.*\b/, opts.binary, /\b.*/);
    }
    return inherit({
      className: "meta",
      begin: beginShebang,
      end: /$/,
      relevance: 0,
      /** @type {ModeCallback} */
      "on:begin": (m, resp) => {
        if (m.index !== 0) resp.ignoreMatch();
      }
    }, opts);
  };
  // Common modes
    const BACKSLASH_ESCAPE = {
    begin: "\\\\[\\s\\S]",
    relevance: 0
  };
  const APOS_STRING_MODE = {
    className: "string",
    begin: "'",
    end: "'",
    illegal: "\\n",
    contains: [ BACKSLASH_ESCAPE ]
  };
  const QUOTE_STRING_MODE = {
    className: "string",
    begin: '"',
    end: '"',
    illegal: "\\n",
    contains: [ BACKSLASH_ESCAPE ]
  };
  const PHRASAL_WORDS_MODE = {
    begin: /\b(a|an|the|are|I'm|isn't|don't|doesn't|won't|but|just|should|pretty|simply|enough|gonna|going|wtf|so|such|will|you|your|they|like|more)\b/
  };
  /**
   * Creates a comment mode
   *
   * @param {string | RegExp} begin
   * @param {string | RegExp} end
   * @param {Mode | {}} [modeOptions]
   * @returns {Partial<Mode>}
   */  const COMMENT = function(begin, end, modeOptions = {}) {
    const mode = inherit({
      className: "comment",
      begin: begin,
      end: end,
      contains: []
    }, modeOptions);
    mode.contains.push(PHRASAL_WORDS_MODE);
    mode.contains.push({
      className: "doctag",
      begin: "(?:TODO|FIXME|NOTE|BUG|OPTIMIZE|HACK|XXX):",
      relevance: 0
    });
    return mode;
  };
  const C_LINE_COMMENT_MODE = COMMENT("//", "$");
  const C_BLOCK_COMMENT_MODE = COMMENT("/\\*", "\\*/");
  const HASH_COMMENT_MODE = COMMENT("#", "$");
  const NUMBER_MODE = {
    className: "number",
    begin: NUMBER_RE,
    relevance: 0
  };
  const C_NUMBER_MODE = {
    className: "number",
    begin: C_NUMBER_RE,
    relevance: 0
  };
  const BINARY_NUMBER_MODE = {
    className: "number",
    begin: BINARY_NUMBER_RE,
    relevance: 0
  };
  const CSS_NUMBER_MODE = {
    className: "number",
    begin: NUMBER_RE + "(" + "%|em|ex|ch|rem" + "|vw|vh|vmin|vmax" + "|cm|mm|in|pt|pc|px" + "|deg|grad|rad|turn" + "|s|ms" + "|Hz|kHz" + "|dpi|dpcm|dppx" + ")?",
    relevance: 0
  };
  const REGEXP_MODE = {
    // this outer rule makes sure we actually have a WHOLE regex and not simply
    // an expression such as:
    //     3 / something
    // (which will then blow up when regex's `illegal` sees the newline)
    begin: /(?=\/[^/\n]*\/)/,
    contains: [ {
      className: "regexp",
      begin: /\//,
      end: /\/[gimuy]*/,
      illegal: /\n/,
      contains: [ BACKSLASH_ESCAPE, {
        begin: /\[/,
        end: /\]/,
        relevance: 0,
        contains: [ BACKSLASH_ESCAPE ]
      } ]
    } ]
  };
  const TITLE_MODE = {
    className: "title",
    begin: IDENT_RE,
    relevance: 0
  };
  const UNDERSCORE_TITLE_MODE = {
    className: "title",
    begin: UNDERSCORE_IDENT_RE,
    relevance: 0
  };
  const METHOD_GUARD = {
    // excludes method names from keyword processing
    begin: "\\.\\s*" + UNDERSCORE_IDENT_RE,
    relevance: 0
  };
  /**
   * Adds end same as begin mechanics to a mode
   *
   * Your mode must include at least a single () match group as that first match
   * group is what is used for comparison
   * @param {Partial<Mode>} mode
   */  const END_SAME_AS_BEGIN = function(mode) {
    return Object.assign(mode, {
      /** @type {ModeCallback} */
      "on:begin": (m, resp) => {
        resp.data._beginMatch = m[1];
      },
      /** @type {ModeCallback} */
      "on:end": (m, resp) => {
        if (resp.data._beginMatch !== m[1]) resp.ignoreMatch();
      }
    });
  };
  var MODES =  Object.freeze({
    __proto__: null,
    IDENT_RE: IDENT_RE,
    UNDERSCORE_IDENT_RE: UNDERSCORE_IDENT_RE,
    NUMBER_RE: NUMBER_RE,
    C_NUMBER_RE: C_NUMBER_RE,
    BINARY_NUMBER_RE: BINARY_NUMBER_RE,
    RE_STARTERS_RE: RE_STARTERS_RE,
    SHEBANG: SHEBANG,
    BACKSLASH_ESCAPE: BACKSLASH_ESCAPE,
    APOS_STRING_MODE: APOS_STRING_MODE,
    QUOTE_STRING_MODE: QUOTE_STRING_MODE,
    PHRASAL_WORDS_MODE: PHRASAL_WORDS_MODE,
    COMMENT: COMMENT,
    C_LINE_COMMENT_MODE: C_LINE_COMMENT_MODE,
    C_BLOCK_COMMENT_MODE: C_BLOCK_COMMENT_MODE,
    HASH_COMMENT_MODE: HASH_COMMENT_MODE,
    NUMBER_MODE: NUMBER_MODE,
    C_NUMBER_MODE: C_NUMBER_MODE,
    BINARY_NUMBER_MODE: BINARY_NUMBER_MODE,
    CSS_NUMBER_MODE: CSS_NUMBER_MODE,
    REGEXP_MODE: REGEXP_MODE,
    TITLE_MODE: TITLE_MODE,
    UNDERSCORE_TITLE_MODE: UNDERSCORE_TITLE_MODE,
    METHOD_GUARD: METHOD_GUARD,
    END_SAME_AS_BEGIN: END_SAME_AS_BEGIN
  });
  // keywords that should have no default relevance value
    const COMMON_KEYWORDS = [ "of", "and", "for", "in", "not", "or", "if", "then", "parent", // common variable name
  "list", // common variable name
  "value" ];
  // compilation
  /**
   * Compiles a language definition result
   *
   * Given the raw result of a language definition (Language), compiles this so
   * that it is ready for highlighting code.
   * @param {Language} language
   * @returns {CompiledLanguage}
   */  function compileLanguage(language) {
    /**
     * Builds a regex with the case sensativility of the current language
     *
     * @param {RegExp | string} value
     * @param {boolean} [global]
     */
    function langRe(value, global) {
      return new RegExp(source(value), "m" + (language.case_insensitive ? "i" : "") + (global ? "g" : ""));
    }
    /**
      Stores multiple regular expressions and allows you to quickly search for
      them all in a string simultaneously - returning the first match.  It does
      this by creating a huge (a|b|c) regex - each individual item wrapped with ()
      and joined by `|` - using match groups to track position.  When a match is
      found checking which position in the array has content allows us to figure
      out which of the original regexes / match groups triggered the match.

      The match object itself (the result of `Regex.exec`) is returned but also
      enhanced by merging in any meta-data that was registered with the regex.
      This is how we keep track of which mode matched, and what type of rule
      (`illegal`, `begin`, end, etc).
    */    class MultiRegex {
      constructor() {
        this.matchIndexes = {};
        // @ts-ignore
                this.regexes = [];
        this.matchAt = 1;
        this.position = 0;
      }
      // @ts-ignore
      addRule(re, opts) {
        opts.position = this.position++;
        // @ts-ignore
                this.matchIndexes[this.matchAt] = opts;
        this.regexes.push([ opts, re ]);
        this.matchAt += countMatchGroups(re) + 1;
      }
      compile() {
        if (this.regexes.length === 0) {
          // avoids the need to check length every time exec is called
          // @ts-ignore
          this.exec = () => null;
        }
        const terminators = this.regexes.map((el => el[1]));
        this.matcherRe = langRe(join(terminators), true);
        this.lastIndex = 0;
      }
      /** @param {string} s */      exec(s) {
        this.matcherRe.lastIndex = this.lastIndex;
        const match = this.matcherRe.exec(s);
        if (!match) {
          return null;
        }
        // eslint-disable-next-line no-undefined
                const i = match.findIndex(((el, i) => i > 0 && el !== undefined));
        // @ts-ignore
                const matchData = this.matchIndexes[i];
        // trim off any earlier non-relevant match groups (ie, the other regex
        // match groups that make up the multi-matcher)
                match.splice(0, i);
        return Object.assign(match, matchData);
      }
    }
    /*
      Created to solve the key deficiently with MultiRegex - there is no way to
      test for multiple matches at a single location.  Why would we need to do
      that?  In the future a more dynamic engine will allow certain matches to be
      ignored.  An example: if we matched say the 3rd regex in a large group but
      decided to ignore it - we'd need to started testing again at the 4th
      regex... but MultiRegex itself gives us no real way to do that.

      So what this class creates MultiRegexs on the fly for whatever search
      position they are needed.

      NOTE: These additional MultiRegex objects are created dynamically.  For most
      grammars most of the time we will never actually need anything more than the
      first MultiRegex - so this shouldn't have too much overhead.

      Say this is our search group, and we match regex3, but wish to ignore it.

        regex1 | regex2 | regex3 | regex4 | regex5    ' ie, startAt = 0

      What we need is a new MultiRegex that only includes the remaining
      possibilities:

        regex4 | regex5                               ' ie, startAt = 3

      This class wraps all that complexity up in a simple API... `startAt` decides
      where in the array of expressions to start doing the matching. It
      auto-increments, so if a match is found at position 2, then startAt will be
      set to 3.  If the end is reached startAt will return to 0.

      MOST of the time the parser will be setting startAt manually to 0.
    */    class ResumableMultiRegex {
      constructor() {
        // @ts-ignore
        this.rules = [];
        // @ts-ignore
                this.multiRegexes = [];
        this.count = 0;
        this.lastIndex = 0;
        this.regexIndex = 0;
      }
      // @ts-ignore
      getMatcher(index) {
        if (this.multiRegexes[index]) return this.multiRegexes[index];
        const matcher = new MultiRegex;
        this.rules.slice(index).forEach((([re, opts]) => matcher.addRule(re, opts)));
        matcher.compile();
        this.multiRegexes[index] = matcher;
        return matcher;
      }
      resumingScanAtSamePosition() {
        return this.regexIndex !== 0;
      }
      considerAll() {
        this.regexIndex = 0;
      }
      // @ts-ignore
      addRule(re, opts) {
        this.rules.push([ re, opts ]);
        if (opts.type === "begin") this.count++;
      }
      /** @param {string} s */      exec(s) {
        const m = this.getMatcher(this.regexIndex);
        m.lastIndex = this.lastIndex;
        let result = m.exec(s);
        // The following is because we have no easy way to say "resume scanning at the
        // existing position but also skip the current rule ONLY". What happens is
        // all prior rules are also skipped which can result in matching the wrong
        // thing. Example of matching "booger":
        // our matcher is [string, "booger", number]
        
        // ....booger....
        // if "booger" is ignored then we'd really need a regex to scan from the
        // SAME position for only: [string, number] but ignoring "booger" (if it
        // was the first match), a simple resume would scan ahead who knows how
        // far looking only for "number", ignoring potential string matches (or
        // future "booger" matches that might be valid.)
        // So what we do: We execute two matchers, one resuming at the same
        // position, but the second full matcher starting at the position after:
        //     /--- resume first regex match here (for [number])
        //     |/---- full match here for [string, "booger", number]
        //     vv
        // ....booger....
        // Which ever results in a match first is then used. So this 3-4 step
        // process essentially allows us to say "match at this position, excluding
        // a prior rule that was ignored".
        
        // 1. Match "booger" first, ignore. Also proves that [string] does non match.
        // 2. Resume matching for [number]
        // 3. Match at index + 1 for [string, "booger", number]
        // 4. If #2 and #3 result in matches, which came first?
                if (this.resumingScanAtSamePosition()) {
          if (result && result.index === this.lastIndex) ; else {
            // use the second matcher result
            const m2 = this.getMatcher(0);
            m2.lastIndex = this.lastIndex + 1;
            result = m2.exec(s);
          }
        }
        if (result) {
          this.regexIndex += result.position + 1;
          if (this.regexIndex === this.count) {
            // wrap-around to considering all matches again
            this.considerAll();
          }
        }
        return result;
      }
    }
    /**
     * Given a mode, builds a huge ResumableMultiRegex that can be used to walk
     * the content and find matches.
     *
     * @param {CompiledMode} mode
     * @returns {ResumableMultiRegex}
     */    function buildModeRegex(mode) {
      const mm = new ResumableMultiRegex;
      mode.contains.forEach((term => mm.addRule(term.begin, {
        rule: term,
        type: "begin"
      })));
      if (mode.terminator_end) {
        mm.addRule(mode.terminator_end, {
          type: "end"
        });
      }
      if (mode.illegal) {
        mm.addRule(mode.illegal, {
          type: "illegal"
        });
      }
      return mm;
    }
    // TODO: We need negative look-behind support to do this properly
    /**
     * Skip a match if it has a preceding dot
     *
     * This is used for `beginKeywords` to prevent matching expressions such as
     * `bob.keyword.do()`. The mode compiler automatically wires this up as a
     * special _internal_ 'on:begin' callback for modes with `beginKeywords`
     * @param {RegExpMatchArray} match
     * @param {CallbackResponse} response
     */    function skipIfhasPrecedingDot(match, response) {
      const before = match.input[match.index - 1];
      if (before === ".") {
        response.ignoreMatch();
      }
    }
    /** skip vs abort vs ignore
     *
     * @skip   - The mode is still entered and exited normally (and contains rules apply),
     *           but all content is held and added to the parent buffer rather than being
     *           output when the mode ends.  Mostly used with `sublanguage` to build up
     *           a single large buffer than can be parsed by sublanguage.
     *
     *             - The mode begin ands ends normally.
     *             - Content matched is added to the parent mode buffer.
     *             - The parser cursor is moved forward normally.
     *
     * @abort  - A hack placeholder until we have ignore.  Aborts the mode (as if it
     *           never matched) but DOES NOT continue to match subsequent `contains`
     *           modes.  Abort is bad/suboptimal because it can result in modes
     *           farther down not getting applied because an earlier rule eats the
     *           content but then aborts.
     *
     *             - The mode does not begin.
     *             - Content matched by `begin` is added to the mode buffer.
     *             - The parser cursor is moved forward accordingly.
     *
     * @ignore - Ignores the mode (as if it never matched) and continues to match any
     *           subsequent `contains` modes.  Ignore isn't technically possible with
     *           the current parser implementation.
     *
     *             - The mode does not begin.
     *             - Content matched by `begin` is ignored.
     *             - The parser cursor is not moved forward.
     */
    /**
     * Compiles an individual mode
     *
     * This can raise an error if the mode contains certain detectable known logic
     * issues.
     * @param {Mode} mode
     * @param {CompiledMode | null} [parent]
     * @returns {CompiledMode | never}
     */    function compileMode(mode, parent) {
      const cmode = /** @type CompiledMode */ mode;
      if (mode.compiled) return cmode;
      mode.compiled = true;
      // __beforeBegin is considered private API, internal use only
            mode.__beforeBegin = null;
      mode.keywords = mode.keywords || mode.beginKeywords;
      let keywordPattern = null;
      if (typeof mode.keywords === "object") {
        keywordPattern = mode.keywords.$pattern;
        delete mode.keywords.$pattern;
      }
      if (mode.keywords) {
        mode.keywords = compileKeywords(mode.keywords, language.case_insensitive);
      }
      // both are not allowed
            if (mode.lexemes && keywordPattern) {
        throw new Error("ERR: Prefer `keywords.$pattern` to `mode.lexemes`, BOTH are not allowed. (see mode reference) ");
      }
      // `mode.lexemes` was the old standard before we added and now recommend
      // using `keywords.$pattern` to pass the keyword pattern
            cmode.keywordPatternRe = langRe(mode.lexemes || keywordPattern || /\w+/, true);
      if (parent) {
        if (mode.beginKeywords) {
          // for languages with keywords that include non-word characters checking for
          // a word boundary is not sufficient, so instead we check for a word boundary
          // or whitespace - this does no harm in any case since our keyword engine
          // doesn't allow spaces in keywords anyways and we still check for the boundary
          // first
          mode.begin = "\\b(" + mode.beginKeywords.split(" ").join("|") + ")(?!\\.)(?=\\b|\\s)";
          mode.__beforeBegin = skipIfhasPrecedingDot;
        }
        if (!mode.begin) mode.begin = /\B|\b/;
        cmode.beginRe = langRe(mode.begin);
        if (mode.endSameAsBegin) mode.end = mode.begin;
        if (!mode.end && !mode.endsWithParent) mode.end = /\B|\b/;
        if (mode.end) cmode.endRe = langRe(mode.end);
        cmode.terminator_end = source(mode.end) || "";
        if (mode.endsWithParent && parent.terminator_end) {
          cmode.terminator_end += (mode.end ? "|" : "") + parent.terminator_end;
        }
      }
      if (mode.illegal) cmode.illegalRe = langRe(mode.illegal);
      // eslint-disable-next-line no-undefined
            if (mode.relevance === undefined) mode.relevance = 1;
      if (!mode.contains) mode.contains = [];
      mode.contains = [].concat(...mode.contains.map((function(c) {
        return expandOrCloneMode(c === "self" ? mode : c);
      })));
      mode.contains.forEach((function(c) {
        compileMode(/** @type Mode */ c, cmode);
      }));
      if (mode.starts) {
        compileMode(mode.starts, parent);
      }
      cmode.matcher = buildModeRegex(cmode);
      return cmode;
    }
    // self is not valid at the top-level
        if (language.contains && language.contains.includes("self")) {
      throw new Error("ERR: contains `self` is not supported at the top-level of a language.  See documentation.");
    }
    // we need a null object, which inherit will guarantee
        language.classNameAliases = inherit(language.classNameAliases || {});
    return compileMode(/** @type Mode */ language);
  }
  /**
   * Determines if a mode has a dependency on it's parent or not
   *
   * If a mode does have a parent dependency then often we need to clone it if
   * it's used in multiple places so that each copy points to the correct parent,
   * where-as modes without a parent can often safely be re-used at the bottom of
   * a mode chain.
   *
   * @param {Mode | null} mode
   * @returns {boolean} - is there a dependency on the parent?
   * */  function dependencyOnParent(mode) {
    if (!mode) return false;
    return mode.endsWithParent || dependencyOnParent(mode.starts);
  }
  /**
   * Expands a mode or clones it if necessary
   *
   * This is necessary for modes with parental dependenceis (see notes on
   * `dependencyOnParent`) and for nodes that have `variants` - which must then be
   * exploded into their own individual modes at compile time.
   *
   * @param {Mode} mode
   * @returns {Mode | Mode[]}
   * */  function expandOrCloneMode(mode) {
    if (mode.variants && !mode.cached_variants) {
      mode.cached_variants = mode.variants.map((function(variant) {
        return inherit(mode, {
          variants: null
        }, variant);
      }));
    }
    // EXPAND
    // if we have variants then essentially "replace" the mode with the variants
    // this happens in compileMode, where this function is called from
        if (mode.cached_variants) {
      return mode.cached_variants;
    }
    // CLONE
    // if we have dependencies on parents then we need a unique
    // instance of ourselves, so we can be reused with many
    // different parents without issue
        if (dependencyOnParent(mode)) {
      return inherit(mode, {
        starts: mode.starts ? inherit(mode.starts) : null
      });
    }
    if (Object.isFrozen(mode)) {
      return inherit(mode);
    }
    // no special dependency issues, just return ourselves
        return mode;
  }
  /***********************************************
    Keywords
  ***********************************************/
  /**
   * Given raw keywords from a language definition, compile them.
   *
   * @param {string | Record<string,string>} rawKeywords
   * @param {boolean} caseInsensitive
   */  function compileKeywords(rawKeywords, caseInsensitive) {
    /** @type KeywordDict */
    const compiledKeywords = {};
    if (typeof rawKeywords === "string") {
      // string
      splitAndCompile("keyword", rawKeywords);
    } else {
      Object.keys(rawKeywords).forEach((function(className) {
        splitAndCompile(className, rawKeywords[className]);
      }));
    }
    return compiledKeywords;
    // ---
    /**
     * Compiles an individual list of keywords
     *
     * Ex: "for if when while|5"
     *
     * @param {string} className
     * @param {string} keywordList
     */    function splitAndCompile(className, keywordList) {
      if (caseInsensitive) {
        keywordList = keywordList.toLowerCase();
      }
      keywordList.split(" ").forEach((function(keyword) {
        const pair = keyword.split("|");
        compiledKeywords[pair[0]] = [ className, scoreForKeyword(pair[0], pair[1]) ];
      }));
    }
  }
  /**
   * Returns the proper score for a given keyword
   *
   * Also takes into account comment keywords, which will be scored 0 UNLESS
   * another score has been manually assigned.
   * @param {string} keyword
   * @param {string} [providedScore]
   */  function scoreForKeyword(keyword, providedScore) {
    // manual scores always win over common keywords
    // so you can force a score of 1 if you really insist
    if (providedScore) {
      return Number(providedScore);
    }
    return commonKeyword(keyword) ? 0 : 1;
  }
  /**
   * Determines if a given keyword is common or not
   *
   * @param {string} keyword */  function commonKeyword(keyword) {
    return COMMON_KEYWORDS.includes(keyword.toLowerCase());
  }
  var version = "10.4.1";
  // @ts-nocheck
    function hasValueOrEmptyAttribute(value) {
    return Boolean(value || value === "");
  }
  function BuildVuePlugin(hljs) {
    const Component = {
      props: [ "language", "code", "autodetect" ],
      data: function() {
        return {
          detectedLanguage: "",
          unknownLanguage: false
        };
      },
      computed: {
        className() {
          if (this.unknownLanguage) return "";
          return "hljs " + this.detectedLanguage;
        },
        highlighted() {
          // no idea what language to use, return raw code
          if (!this.autoDetect && !hljs.getLanguage(this.language)) {
            console.warn(`The language "${this.language}" you specified could not be found.`);
            this.unknownLanguage = true;
            return escapeHTML(this.code);
          }
          let result;
          if (this.autoDetect) {
            result = hljs.highlightAuto(this.code);
            this.detectedLanguage = result.language;
          } else {
            result = hljs.highlight(this.language, this.code, this.ignoreIllegals);
            this.detectedLanguage = this.language;
          }
          return result.value;
        },
        autoDetect() {
          return !this.language || hasValueOrEmptyAttribute(this.autodetect);
        },
        ignoreIllegals() {
          return true;
        }
      },
      // this avoids needing to use a whole Vue compilation pipeline just
      // to build Highlight.js
      render(createElement) {
        return createElement("pre", {}, [ createElement("code", {
          class: this.className,
          domProps: {
            innerHTML: this.highlighted
          }
        }) ]);
      }
    };
    const VuePlugin = {
      install(Vue) {
        Vue.component("highlightjs", Component);
      }
    };
    return {
      Component: Component,
      VuePlugin: VuePlugin
    };
  }
  /*
  Syntax highlighting with language autodetection.
  https://highlightjs.org/
  */  const escape$1 = escapeHTML;
  const inherit$1 = inherit;
  const {nodeStream: nodeStream$1, mergeStreams: mergeStreams$1} = utils;
  const NO_MATCH = Symbol("nomatch");
  /**
   * @param {any} hljs - object that is extended (legacy)
   * @returns {HLJSApi}
   */  const HLJS = function(hljs) {
    // Convenience variables for build-in objects
    /** @type {unknown[]} */
    const ArrayProto = [];
    // Global internal variables used within the highlight.js library.
    /** @type {Record<string, Language>} */    const languages = Object.create(null);
    /** @type {Record<string, string>} */    const aliases = Object.create(null);
    /** @type {HLJSPlugin[]} */    const plugins = [];
    // safe/production mode - swallows more errors, tries to keep running
    // even if a single syntax or parse hits a fatal error
        let SAFE_MODE = true;
    const fixMarkupRe = /(^(<[^>]+>|\t|)+|\n)/gm;
    const LANGUAGE_NOT_FOUND = "Could not find the language '{}', did you forget to load/include a language module?";
    /** @type {Language} */    const PLAINTEXT_LANGUAGE = {
      disableAutodetect: true,
      name: "Plain text",
      contains: []
    };
    // Global options used when within external APIs. This is modified when
    // calling the `hljs.configure` function.
    /** @type HLJSOptions */    let options = {
      noHighlightRe: /^(no-?highlight)$/i,
      languageDetectRe: /\blang(?:uage)?-([\w-]+)\b/i,
      classPrefix: "hljs-",
      tabReplace: null,
      useBR: false,
      languages: null,
      // beta configuration options, subject to change, welcome to discuss
      // https://github.com/highlightjs/highlight.js/issues/1086
      __emitter: TokenTreeEmitter
    };
    /* Utility functions */
    /**
     * Tests a language name to see if highlighting should be skipped
     * @param {string} languageName
     */    function shouldNotHighlight(languageName) {
      return options.noHighlightRe.test(languageName);
    }
    /**
     * @param {HighlightedHTMLElement} block - the HTML element to determine language for
     */    function blockLanguage(block) {
      let classes = block.className + " ";
      classes += block.parentNode ? block.parentNode.className : "";
      // language-* takes precedence over non-prefixed class names.
            const match = options.languageDetectRe.exec(classes);
      if (match) {
        const language = getLanguage(match[1]);
        if (!language) {
          console.warn(LANGUAGE_NOT_FOUND.replace("{}", match[1]));
          console.warn("Falling back to no-highlight mode for this block.", block);
        }
        return language ? match[1] : "no-highlight";
      }
      return classes.split(/\s+/).find((_class => shouldNotHighlight(_class) || getLanguage(_class)));
    }
    /**
     * Core highlighting function.
     *
     * @param {string} languageName - the language to use for highlighting
     * @param {string} code - the code to highlight
     * @param {boolean} [ignoreIllegals] - whether to ignore illegal matches, default is to bail
     * @param {CompiledMode} [continuation] - current continuation mode, if any
     *
     * @returns {HighlightResult} Result - an object that represents the result
     * @property {string} language - the language name
     * @property {number} relevance - the relevance score
     * @property {string} value - the highlighted HTML code
     * @property {string} code - the original raw code
     * @property {CompiledMode} top - top of the current mode stack
     * @property {boolean} illegal - indicates whether any illegal matches were found
    */    function highlight(languageName, code, ignoreIllegals, continuation) {
      /** @type {{ code: string, language: string, result?: any }} */
      const context = {
        code: code,
        language: languageName
      };
      // the plugin can change the desired language or the code to be highlighted
      // just be changing the object it was passed
            fire("before:highlight", context);
      // a before plugin can usurp the result completely by providing it's own
      // in which case we don't even need to call highlight
            const result = context.result ? context.result : _highlight(context.language, context.code, ignoreIllegals, continuation);
      result.code = context.code;
      // the plugin can change anything in result to suite it
            fire("after:highlight", result);
      return result;
    }
    /**
     * private highlight that's used internally and does not fire callbacks
     *
     * @param {string} languageName - the language to use for highlighting
     * @param {string} code - the code to highlight
     * @param {boolean} [ignoreIllegals] - whether to ignore illegal matches, default is to bail
     * @param {CompiledMode} [continuation] - current continuation mode, if any
     * @returns {HighlightResult} - result of the highlight operation
    */    function _highlight(languageName, code, ignoreIllegals, continuation) {
      const codeToHighlight = code;
      /**
       * Return keyword data if a match is a keyword
       * @param {CompiledMode} mode - current mode
       * @param {RegExpMatchArray} match - regexp match data
       * @returns {KeywordData | false}
       */      function keywordData(mode, match) {
        const matchText = language.case_insensitive ? match[0].toLowerCase() : match[0];
        return Object.prototype.hasOwnProperty.call(mode.keywords, matchText) && mode.keywords[matchText];
      }
      function processKeywords() {
        if (!top.keywords) {
          emitter.addText(modeBuffer);
          return;
        }
        let lastIndex = 0;
        top.keywordPatternRe.lastIndex = 0;
        let match = top.keywordPatternRe.exec(modeBuffer);
        let buf = "";
        while (match) {
          buf += modeBuffer.substring(lastIndex, match.index);
          const data = keywordData(top, match);
          if (data) {
            const [kind, keywordRelevance] = data;
            emitter.addText(buf);
            buf = "";
            relevance += keywordRelevance;
            const cssClass = language.classNameAliases[kind] || kind;
            emitter.addKeyword(match[0], cssClass);
          } else {
            buf += match[0];
          }
          lastIndex = top.keywordPatternRe.lastIndex;
          match = top.keywordPatternRe.exec(modeBuffer);
        }
        buf += modeBuffer.substr(lastIndex);
        emitter.addText(buf);
      }
      function processSubLanguage() {
        if (modeBuffer === "") return;
        /** @type HighlightResult */        let result = null;
        if (typeof top.subLanguage === "string") {
          if (!languages[top.subLanguage]) {
            emitter.addText(modeBuffer);
            return;
          }
          result = _highlight(top.subLanguage, modeBuffer, true, continuations[top.subLanguage]);
          continuations[top.subLanguage] = /** @type {CompiledMode} */ result.top;
        } else {
          result = highlightAuto(modeBuffer, top.subLanguage.length ? top.subLanguage : null);
        }
        // Counting embedded language score towards the host language may be disabled
        // with zeroing the containing mode relevance. Use case in point is Markdown that
        // allows XML everywhere and makes every XML snippet to have a much larger Markdown
        // score.
                if (top.relevance > 0) {
          relevance += result.relevance;
        }
        emitter.addSublanguage(result.emitter, result.language);
      }
      function processBuffer() {
        if (top.subLanguage != null) {
          processSubLanguage();
        } else {
          processKeywords();
        }
        modeBuffer = "";
      }
      /**
       * @param {Mode} mode - new mode to start
       */      function startNewMode(mode) {
        if (mode.className) {
          emitter.openNode(language.classNameAliases[mode.className] || mode.className);
        }
        top = Object.create(mode, {
          parent: {
            value: top
          }
        });
        return top;
      }
      /**
       * @param {CompiledMode } mode - the mode to potentially end
       * @param {RegExpMatchArray} match - the latest match
       * @param {string} matchPlusRemainder - match plus remainder of content
       * @returns {CompiledMode | void} - the next mode, or if void continue on in current mode
       */      function endOfMode(mode, match, matchPlusRemainder) {
        let matched = startsWith(mode.endRe, matchPlusRemainder);
        if (matched) {
          if (mode["on:end"]) {
            const resp = new Response(mode);
            mode["on:end"](match, resp);
            if (resp.ignore) matched = false;
          }
          if (matched) {
            while (mode.endsParent && mode.parent) {
              mode = mode.parent;
            }
            return mode;
          }
        }
        // even if on:end fires an `ignore` it's still possible
        // that we might trigger the end node because of a parent mode
                if (mode.endsWithParent) {
          return endOfMode(mode.parent, match, matchPlusRemainder);
        }
      }
      /**
       * Handle matching but then ignoring a sequence of text
       *
       * @param {string} lexeme - string containing full match text
       */      function doIgnore(lexeme) {
        if (top.matcher.regexIndex === 0) {
          // no more regexs to potentially match here, so we move the cursor forward one
          // space
          modeBuffer += lexeme[0];
          return 1;
        } else {
          // no need to move the cursor, we still have additional regexes to try and
          // match at this very spot
          resumeScanAtSamePosition = true;
          return 0;
        }
      }
      /**
       * Handle the start of a new potential mode match
       *
       * @param {EnhancedMatch} match - the current match
       * @returns {number} how far to advance the parse cursor
       */      function doBeginMatch(match) {
        const lexeme = match[0];
        const newMode = match.rule;
        const resp = new Response(newMode);
        // first internal before callbacks, then the public ones
                const beforeCallbacks = [ newMode.__beforeBegin, newMode["on:begin"] ];
        for (const cb of beforeCallbacks) {
          if (!cb) continue;
          cb(match, resp);
          if (resp.ignore) return doIgnore(lexeme);
        }
        if (newMode && newMode.endSameAsBegin) {
          newMode.endRe = escape(lexeme);
        }
        if (newMode.skip) {
          modeBuffer += lexeme;
        } else {
          if (newMode.excludeBegin) {
            modeBuffer += lexeme;
          }
          processBuffer();
          if (!newMode.returnBegin && !newMode.excludeBegin) {
            modeBuffer = lexeme;
          }
        }
        startNewMode(newMode);
        // if (mode["after:begin"]) {
        //   let resp = new Response(mode);
        //   mode["after:begin"](match, resp);
        // }
                return newMode.returnBegin ? 0 : lexeme.length;
      }
      /**
       * Handle the potential end of mode
       *
       * @param {RegExpMatchArray} match - the current match
       */      function doEndMatch(match) {
        const lexeme = match[0];
        const matchPlusRemainder = codeToHighlight.substr(match.index);
        const endMode = endOfMode(top, match, matchPlusRemainder);
        if (!endMode) {
          return NO_MATCH;
        }
        const origin = top;
        if (origin.skip) {
          modeBuffer += lexeme;
        } else {
          if (!(origin.returnEnd || origin.excludeEnd)) {
            modeBuffer += lexeme;
          }
          processBuffer();
          if (origin.excludeEnd) {
            modeBuffer = lexeme;
          }
        }
        do {
          if (top.className) {
            emitter.closeNode();
          }
          if (!top.skip && !top.subLanguage) {
            relevance += top.relevance;
          }
          top = top.parent;
        } while (top !== endMode.parent);
        if (endMode.starts) {
          if (endMode.endSameAsBegin) {
            endMode.starts.endRe = endMode.endRe;
          }
          startNewMode(endMode.starts);
        }
        return origin.returnEnd ? 0 : lexeme.length;
      }
      function processContinuations() {
        const list = [];
        for (let current = top; current !== language; current = current.parent) {
          if (current.className) {
            list.unshift(current.className);
          }
        }
        list.forEach((item => emitter.openNode(item)));
      }
      /** @type {{type?: MatchType, index?: number, rule?: Mode}}} */      let lastMatch = {};
      /**
       *  Process an individual match
       *
       * @param {string} textBeforeMatch - text preceeding the match (since the last match)
       * @param {EnhancedMatch} [match] - the match itself
       */      function processLexeme(textBeforeMatch, match) {
        const lexeme = match && match[0];
        // add non-matched text to the current mode buffer
                modeBuffer += textBeforeMatch;
        if (lexeme == null) {
          processBuffer();
          return 0;
        }
        // we've found a 0 width match and we're stuck, so we need to advance
        // this happens when we have badly behaved rules that have optional matchers to the degree that
        // sometimes they can end up matching nothing at all
        // Ref: https://github.com/highlightjs/highlight.js/issues/2140
                if (lastMatch.type === "begin" && match.type === "end" && lastMatch.index === match.index && lexeme === "") {
          // spit the "skipped" character that our regex choked on back into the output sequence
          modeBuffer += codeToHighlight.slice(match.index, match.index + 1);
          if (!SAFE_MODE) {
            /** @type {AnnotatedError} */
            const err = new Error("0 width match regex");
            err.languageName = languageName;
            err.badRule = lastMatch.rule;
            throw err;
          }
          return 1;
        }
        lastMatch = match;
        if (match.type === "begin") {
          return doBeginMatch(match);
        } else if (match.type === "illegal" && !ignoreIllegals) {
          // illegal match, we do not continue processing
          /** @type {AnnotatedError} */
          const err = new Error('Illegal lexeme "' + lexeme + '" for mode "' + (top.className || "<unnamed>") + '"');
          err.mode = top;
          throw err;
        } else if (match.type === "end") {
          const processed = doEndMatch(match);
          if (processed !== NO_MATCH) {
            return processed;
          }
        }
        // edge case for when illegal matches $ (end of line) which is technically
        // a 0 width match but not a begin/end match so it's not caught by the
        // first handler (when ignoreIllegals is true)
                if (match.type === "illegal" && lexeme === "") {
          // advance so we aren't stuck in an infinite loop
          return 1;
        }
        // infinite loops are BAD, this is a last ditch catch all. if we have a
        // decent number of iterations yet our index (cursor position in our
        // parsing) still 3x behind our index then something is very wrong
        // so we bail
                if (iterations > 1e5 && iterations > match.index * 3) {
          const err = new Error("potential infinite loop, way more iterations than matches");
          throw err;
        }
        /*
        Why might be find ourselves here?  Only one occasion now.  An end match that was
        triggered but could not be completed.  When might this happen?  When an `endSameasBegin`
        rule sets the end rule to a specific match.  Since the overall mode termination rule that's
        being used to scan the text isn't recompiled that means that any match that LOOKS like
        the end (but is not, because it is not an exact match to the beginning) will
        end up here.  A definite end match, but when `doEndMatch` tries to "reapply"
        the end rule and fails to match, we wind up here, and just silently ignore the end.

        This causes no real harm other than stopping a few times too many.
        */        modeBuffer += lexeme;
        return lexeme.length;
      }
      const language = getLanguage(languageName);
      if (!language) {
        console.error(LANGUAGE_NOT_FOUND.replace("{}", languageName));
        throw new Error('Unknown language: "' + languageName + '"');
      }
      const md = compileLanguage(language);
      let result = "";
      /** @type {CompiledMode} */      let top = continuation || md;
      /** @type Record<string,CompiledMode> */      const continuations = {};
 // keep continuations for sub-languages
            const emitter = new options.__emitter(options);
      processContinuations();
      let modeBuffer = "";
      let relevance = 0;
      let index = 0;
      let iterations = 0;
      let resumeScanAtSamePosition = false;
      try {
        top.matcher.considerAll();
        for (;;) {
          iterations++;
          if (resumeScanAtSamePosition) {
            // only regexes not matched previously will now be
            // considered for a potential match
            resumeScanAtSamePosition = false;
          } else {
            top.matcher.considerAll();
          }
          top.matcher.lastIndex = index;
          const match = top.matcher.exec(codeToHighlight);
          // console.log("match", match[0], match.rule && match.rule.begin)
                    if (!match) break;
          const beforeMatch = codeToHighlight.substring(index, match.index);
          const processedCount = processLexeme(beforeMatch, match);
          index = match.index + processedCount;
        }
        processLexeme(codeToHighlight.substr(index));
        emitter.closeAllNodes();
        emitter.finalize();
        result = emitter.toHTML();
        return {
          relevance: relevance,
          value: result,
          language: languageName,
          illegal: false,
          emitter: emitter,
          top: top
        };
      } catch (err) {
        if (err.message && err.message.includes("Illegal")) {
          return {
            illegal: true,
            illegalBy: {
              msg: err.message,
              context: codeToHighlight.slice(index - 100, index + 100),
              mode: err.mode
            },
            sofar: result,
            relevance: 0,
            value: escape$1(codeToHighlight),
            emitter: emitter
          };
        } else if (SAFE_MODE) {
          return {
            illegal: false,
            relevance: 0,
            value: escape$1(codeToHighlight),
            emitter: emitter,
            language: languageName,
            top: top,
            errorRaised: err
          };
        } else {
          throw err;
        }
      }
    }
    /**
     * returns a valid highlight result, without actually doing any actual work,
     * auto highlight starts with this and it's possible for small snippets that
     * auto-detection may not find a better match
     * @param {string} code
     * @returns {HighlightResult}
     */    function justTextHighlightResult(code) {
      const result = {
        relevance: 0,
        emitter: new options.__emitter(options),
        value: escape$1(code),
        illegal: false,
        top: PLAINTEXT_LANGUAGE
      };
      result.emitter.addText(code);
      return result;
    }
    /**
    Highlighting with language detection. Accepts a string with the code to
    highlight. Returns an object with the following properties:

    - language (detected language)
    - relevance (int)
    - value (an HTML string with highlighting markup)
    - second_best (object with the same structure for second-best heuristically
      detected language, may be absent)

      @param {string} code
      @param {Array<string>} [languageSubset]
      @returns {AutoHighlightResult}
    */    function highlightAuto(code, languageSubset) {
      languageSubset = languageSubset || options.languages || Object.keys(languages);
      const plaintext = justTextHighlightResult(code);
      const results = languageSubset.filter(getLanguage).filter(autoDetection).map((name => _highlight(name, code, false)));
      results.unshift(plaintext);
 // plaintext is always an option
            const sorted = results.sort(((a, b) => {
        // sort base on relevance
        if (a.relevance !== b.relevance) return b.relevance - a.relevance;
        // always award the tie to the base language
        // ie if C++ and Arduino are tied, it's more likely to be C++
                if (a.language && b.language) {
          if (getLanguage(a.language).supersetOf === b.language) {
            return 1;
          } else if (getLanguage(b.language).supersetOf === a.language) {
            return -1;
          }
        }
        // otherwise say they are equal, which has the effect of sorting on
        // relevance while preserving the original ordering - which is how ties
        // have historically been settled, ie the language that comes first always
        // wins in the case of a tie
                return 0;
      }));
      const [best, secondBest] = sorted;
      /** @type {AutoHighlightResult} */      const result = best;
      result.second_best = secondBest;
      return result;
    }
    /**
    Post-processing of the highlighted markup:

    - replace TABs with something more useful
    - replace real line-breaks with '<br>' for non-pre containers

      @param {string} html
      @returns {string}
    */    function fixMarkup(html) {
      if (!(options.tabReplace || options.useBR)) {
        return html;
      }
      return html.replace(fixMarkupRe, (match => {
        if (match === "\n") {
          return options.useBR ? "<br>" : match;
        } else if (options.tabReplace) {
          return match.replace(/\t/g, options.tabReplace);
        }
        return match;
      }));
    }
    /**
     * Builds new class name for block given the language name
     *
     * @param {string} prevClassName
     * @param {string} [currentLang]
     * @param {string} [resultLang]
     */    function buildClassName(prevClassName, currentLang, resultLang) {
      const language = currentLang ? aliases[currentLang] : resultLang;
      const result = [ prevClassName.trim() ];
      if (!prevClassName.match(/\bhljs\b/)) {
        result.push("hljs");
      }
      if (!prevClassName.includes(language)) {
        result.push(language);
      }
      return result.join(" ").trim();
    }
    /**
     * Applies highlighting to a DOM node containing code. Accepts a DOM node and
     * two optional parameters for fixMarkup.
     *
     * @param {HighlightedHTMLElement} element - the HTML element to highlight
    */    function highlightBlock(element) {
      /** @type HTMLElement */
      let node = null;
      const language = blockLanguage(element);
      if (shouldNotHighlight(language)) return;
      fire("before:highlightBlock", {
        block: element,
        language: language
      });
      if (options.useBR) {
        node = document.createElement("div");
        node.innerHTML = element.innerHTML.replace(/\n/g, "").replace(/<br[ /]*>/g, "\n");
      } else {
        node = element;
      }
      const text = node.textContent;
      const result = language ? highlight(language, text, true) : highlightAuto(text);
      const originalStream = nodeStream$1(node);
      if (originalStream.length) {
        const resultNode = document.createElement("div");
        resultNode.innerHTML = result.value;
        result.value = mergeStreams$1(originalStream, nodeStream$1(resultNode), text);
      }
      result.value = fixMarkup(result.value);
      fire("after:highlightBlock", {
        block: element,
        result: result
      });
      element.innerHTML = result.value;
      element.className = buildClassName(element.className, language, result.language);
      element.result = {
        language: result.language,
        // TODO: remove with version 11.0
        re: result.relevance,
        relavance: result.relevance
      };
      if (result.second_best) {
        element.second_best = {
          language: result.second_best.language,
          // TODO: remove with version 11.0
          re: result.second_best.relevance,
          relavance: result.second_best.relevance
        };
      }
    }
    /**
     * Updates highlight.js global options with the passed options
     *
     * @param {Partial<HLJSOptions>} userOptions
     */    function configure(userOptions) {
      if (userOptions.useBR) {
        console.warn("'useBR' option is deprecated and will be removed entirely in v11.0");
        console.warn("Please see https://github.com/highlightjs/highlight.js/issues/2559");
      }
      options = inherit$1(options, userOptions);
    }
    /**
     * Highlights to all <pre><code> blocks on a page
     *
     * @type {Function & {called?: boolean}}
     */    const initHighlighting = () => {
      if (initHighlighting.called) return;
      initHighlighting.called = true;
      const blocks = document.querySelectorAll("pre code");
      ArrayProto.forEach.call(blocks, highlightBlock);
    };
    // Higlights all when DOMContentLoaded fires
        function initHighlightingOnLoad() {
      // @ts-ignore
      window.addEventListener("DOMContentLoaded", initHighlighting, false);
    }
    /**
     * Register a language grammar module
     *
     * @param {string} languageName
     * @param {LanguageFn} languageDefinition
     */    function registerLanguage(languageName, languageDefinition) {
      let lang = null;
      try {
        lang = languageDefinition(hljs);
      } catch (error) {
        console.error("Language definition for '{}' could not be registered.".replace("{}", languageName));
        // hard or soft error
                if (!SAFE_MODE) {
          throw error;
        } else {
          console.error(error);
        }
        // languages that have serious errors are replaced with essentially a
        // "plaintext" stand-in so that the code blocks will still get normal
        // css classes applied to them - and one bad language won't break the
        // entire highlighter
                lang = PLAINTEXT_LANGUAGE;
      }
      // give it a temporary name if it doesn't have one in the meta-data
            if (!lang.name) lang.name = languageName;
      languages[languageName] = lang;
      lang.rawDefinition = languageDefinition.bind(null, hljs);
      if (lang.aliases) {
        registerAliases(lang.aliases, {
          languageName: languageName
        });
      }
    }
    /**
     * @returns {string[]} List of language internal names
     */    function listLanguages() {
      return Object.keys(languages);
    }
    /**
      intended usage: When one language truly requires another

      Unlike `getLanguage`, this will throw when the requested language
      is not available.

      @param {string} name - name of the language to fetch/require
      @returns {Language | never}
    */    function requireLanguage(name) {
      console.warn("requireLanguage is deprecated and will be removed entirely in the future.");
      console.warn("Please see https://github.com/highlightjs/highlight.js/pull/2844");
      const lang = getLanguage(name);
      if (lang) {
        return lang;
      }
      const err = new Error("The '{}' language is required, but not loaded.".replace("{}", name));
      throw err;
    }
    /**
     * @param {string} name - name of the language to retrieve
     * @returns {Language | undefined}
     */    function getLanguage(name) {
      name = (name || "").toLowerCase();
      return languages[name] || languages[aliases[name]];
    }
    /**
     *
     * @param {string|string[]} aliasList - single alias or list of aliases
     * @param {{languageName: string}} opts
     */    function registerAliases(aliasList, {languageName: languageName}) {
      if (typeof aliasList === "string") {
        aliasList = [ aliasList ];
      }
      aliasList.forEach((alias => {
        aliases[alias] = languageName;
      }));
    }
    /**
     * Determines if a given language has auto-detection enabled
     * @param {string} name - name of the language
     */    function autoDetection(name) {
      const lang = getLanguage(name);
      return lang && !lang.disableAutodetect;
    }
    /**
     * @param {HLJSPlugin} plugin
     */    function addPlugin(plugin) {
      plugins.push(plugin);
    }
    /**
     *
     * @param {PluginEvent} event
     * @param {any} args
     */    function fire(event, args) {
      const cb = event;
      plugins.forEach((function(plugin) {
        if (plugin[cb]) {
          plugin[cb](args);
        }
      }));
    }
    /**
    Note: fixMarkup is deprecated and will be removed entirely in v11

    @param {string} arg
    @returns {string}
    */    function deprecateFixMarkup(arg) {
      console.warn("fixMarkup is deprecated and will be removed entirely in v11.0");
      console.warn("Please see https://github.com/highlightjs/highlight.js/issues/2534");
      return fixMarkup(arg);
    }
    /* Interface definition */    Object.assign(hljs, {
      highlight: highlight,
      highlightAuto: highlightAuto,
      fixMarkup: deprecateFixMarkup,
      highlightBlock: highlightBlock,
      configure: configure,
      initHighlighting: initHighlighting,
      initHighlightingOnLoad: initHighlightingOnLoad,
      registerLanguage: registerLanguage,
      listLanguages: listLanguages,
      getLanguage: getLanguage,
      registerAliases: registerAliases,
      requireLanguage: requireLanguage,
      autoDetection: autoDetection,
      inherit: inherit$1,
      addPlugin: addPlugin,
      // plugins for frameworks
      vuePlugin: BuildVuePlugin(hljs).VuePlugin
    });
    hljs.debugMode = function() {
      SAFE_MODE = false;
    };
    hljs.safeMode = function() {
      SAFE_MODE = true;
    };
    hljs.versionString = version;
    for (const key in MODES) {
      // @ts-ignore
      if (typeof MODES[key] === "object") {
        // @ts-ignore
        deepFreezeEs6(MODES[key]);
      }
    }
    // merge all the modes/regexs into our main object
        Object.assign(hljs, MODES);
    return hljs;
  };
  // export an "instance" of the highlighter
    var highlight = HLJS({});
  var core = highlight;
  /*
  Language: ActionScript
  Author: Alexander Myadzel <myadzel@gmail.com>
  Category: scripting
  */
  /** @type LanguageFn */  function actionscript(hljs) {
    const IDENT_RE = "[a-zA-Z_$][a-zA-Z0-9_$]*";
    const IDENT_FUNC_RETURN_TYPE_RE = "([*]|[a-zA-Z_$][a-zA-Z0-9_$]*)";
    const AS3_REST_ARG_MODE = {
      className: "rest_arg",
      begin: "[.]{3}",
      end: IDENT_RE,
      relevance: 10
    };
    return {
      name: "ActionScript",
      aliases: [ "as" ],
      keywords: {
        keyword: "as break case catch class const continue default delete do dynamic each " + "else extends final finally for function get if implements import in include " + "instanceof interface internal is namespace native new override package private " + "protected public return set static super switch this throw try typeof use var void " + "while with",
        literal: "true false null undefined"
      },
      contains: [ hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, hljs.C_NUMBER_MODE, {
        className: "class",
        beginKeywords: "package",
        end: /\{/,
        contains: [ hljs.TITLE_MODE ]
      }, {
        className: "class",
        beginKeywords: "class interface",
        end: /\{/,
        excludeEnd: true,
        contains: [ {
          beginKeywords: "extends implements"
        }, hljs.TITLE_MODE ]
      }, {
        className: "meta",
        beginKeywords: "import include",
        end: ";",
        keywords: {
          "meta-keyword": "import include"
        }
      }, {
        className: "function",
        beginKeywords: "function",
        end: "[{;]",
        excludeEnd: true,
        illegal: "\\S",
        contains: [ hljs.TITLE_MODE, {
          className: "params",
          begin: "\\(",
          end: "\\)",
          contains: [ hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, AS3_REST_ARG_MODE ]
        }, {
          begin: ":\\s*" + IDENT_FUNC_RETURN_TYPE_RE
        } ]
      }, hljs.METHOD_GUARD ],
      illegal: /#/
    };
  }
  var actionscript_1 = actionscript;
  /*
  Language: Apache config
  Author: Ruslan Keba <rukeba@gmail.com>
  Contributors: Ivan Sagalaev <maniac@softwaremaniacs.org>
  Website: https://httpd.apache.org
  Description: language definition for Apache configuration files (httpd.conf & .htaccess)
  Category: common, config
  */
  /** @type LanguageFn */  function apache(hljs) {
    const NUMBER_REF = {
      className: "number",
      begin: "[\\$%]\\d+"
    };
    const NUMBER = {
      className: "number",
      begin: "\\d+"
    };
    const IP_ADDRESS = {
      className: "number",
      begin: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d{1,5})?"
    };
    const PORT_NUMBER = {
      className: "number",
      begin: ":\\d{1,5}"
    };
    return {
      name: "Apache config",
      aliases: [ "apacheconf" ],
      case_insensitive: true,
      contains: [ hljs.HASH_COMMENT_MODE, {
        className: "section",
        begin: "</?",
        end: ">",
        contains: [ IP_ADDRESS, PORT_NUMBER, 
        // low relevance prevents us from claming XML/HTML where this rule would
        // match strings inside of XML tags
        hljs.inherit(hljs.QUOTE_STRING_MODE, {
          relevance: 0
        }) ]
      }, {
        className: "attribute",
        begin: /\w+/,
        relevance: 0,
        // keywords aren’t needed for highlighting per se, they only boost relevance
        // for a very generally defined mode (starts with a word, ends with line-end
        keywords: {
          nomarkup: "order deny allow setenv rewriterule rewriteengine rewritecond documentroot " + "sethandler errordocument loadmodule options header listen serverroot " + "servername"
        },
        starts: {
          end: /$/,
          relevance: 0,
          keywords: {
            literal: "on off all deny allow"
          },
          contains: [ {
            className: "meta",
            begin: "\\s\\[",
            end: "\\]$"
          }, {
            className: "variable",
            begin: "[\\$%]\\{",
            end: "\\}",
            contains: [ "self", NUMBER_REF ]
          }, IP_ADDRESS, NUMBER, hljs.QUOTE_STRING_MODE ]
        }
      } ],
      illegal: /\S/
    };
  }
  var apache_1 = apache;
  /*
  Language: ARM Assembly
  Author: Dan Panzarella <alsoelp@gmail.com>
  Description: ARM Assembly including Thumb and Thumb2 instructions
  Category: assembler
  */
  /** @type LanguageFn */  function armasm(hljs) {
    // local labels: %?[FB]?[AT]?\d{1,2}\w+
    const COMMENT = {
      variants: [ hljs.COMMENT("^[ \\t]*(?=#)", "$", {
        relevance: 0,
        excludeBegin: true
      }), hljs.COMMENT("[;@]", "$", {
        relevance: 0
      }), hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE ]
    };
    return {
      name: "ARM Assembly",
      case_insensitive: true,
      aliases: [ "arm" ],
      keywords: {
        $pattern: "\\.?" + hljs.IDENT_RE,
        meta: 
        // GNU preprocs
        ".2byte .4byte .align .ascii .asciz .balign .byte .code .data .else .end .endif .endm .endr .equ .err .exitm .extern .global .hword .if .ifdef .ifndef .include .irp .long .macro .rept .req .section .set .skip .space .text .word .arm .thumb .code16 .code32 .force_thumb .thumb_func .ltorg " + 
        // ARM directives
        "ALIAS ALIGN ARM AREA ASSERT ATTR CN CODE CODE16 CODE32 COMMON CP DATA DCB DCD DCDU DCDO DCFD DCFDU DCI DCQ DCQU DCW DCWU DN ELIF ELSE END ENDFUNC ENDIF ENDP ENTRY EQU EXPORT EXPORTAS EXTERN FIELD FILL FUNCTION GBLA GBLL GBLS GET GLOBAL IF IMPORT INCBIN INCLUDE INFO KEEP LCLA LCLL LCLS LTORG MACRO MAP MEND MEXIT NOFP OPT PRESERVE8 PROC QN READONLY RELOC REQUIRE REQUIRE8 RLIST FN ROUT SETA SETL SETS SN SPACE SUBT THUMB THUMBX TTL WHILE WEND ",
        built_in: "r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 " + // standard registers
        "pc lr sp ip sl sb fp " + // typical regs plus backward compatibility
        "a1 a2 a3 a4 v1 v2 v3 v4 v5 v6 v7 v8 f0 f1 f2 f3 f4 f5 f6 f7 " + // more regs and fp
        "p0 p1 p2 p3 p4 p5 p6 p7 p8 p9 p10 p11 p12 p13 p14 p15 " + // coprocessor regs
        "c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 c10 c11 c12 c13 c14 c15 " + // more coproc
        "q0 q1 q2 q3 q4 q5 q6 q7 q8 q9 q10 q11 q12 q13 q14 q15 " + // advanced SIMD NEON regs
        // program status registers
        "cpsr_c cpsr_x cpsr_s cpsr_f cpsr_cx cpsr_cxs cpsr_xs cpsr_xsf cpsr_sf cpsr_cxsf " + "spsr_c spsr_x spsr_s spsr_f spsr_cx spsr_cxs spsr_xs spsr_xsf spsr_sf spsr_cxsf " + 
        // NEON and VFP registers
        "s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 " + "s16 s17 s18 s19 s20 s21 s22 s23 s24 s25 s26 s27 s28 s29 s30 s31 " + "d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 d10 d11 d12 d13 d14 d15 " + "d16 d17 d18 d19 d20 d21 d22 d23 d24 d25 d26 d27 d28 d29 d30 d31 " + "{PC} {VAR} {TRUE} {FALSE} {OPT} {CONFIG} {ENDIAN} {CODESIZE} {CPU} {FPU} {ARCHITECTURE} {PCSTOREOFFSET} {ARMASM_VERSION} {INTER} {ROPI} {RWPI} {SWST} {NOSWST} . @"
      },
      contains: [ {
        className: "keyword",
        begin: "\\b(" + // mnemonics
        "adc|" + "(qd?|sh?|u[qh]?)?add(8|16)?|usada?8|(q|sh?|u[qh]?)?(as|sa)x|" + "and|adrl?|sbc|rs[bc]|asr|b[lx]?|blx|bxj|cbn?z|tb[bh]|bic|" + "bfc|bfi|[su]bfx|bkpt|cdp2?|clz|clrex|cmp|cmn|cpsi[ed]|cps|" + "setend|dbg|dmb|dsb|eor|isb|it[te]{0,3}|lsl|lsr|ror|rrx|" + "ldm(([id][ab])|f[ds])?|ldr((s|ex)?[bhd])?|movt?|mvn|mra|mar|" + "mul|[us]mull|smul[bwt][bt]|smu[as]d|smmul|smmla|" + "mla|umlaal|smlal?([wbt][bt]|d)|mls|smlsl?[ds]|smc|svc|sev|" + "mia([bt]{2}|ph)?|mrr?c2?|mcrr2?|mrs|msr|orr|orn|pkh(tb|bt)|rbit|" + "rev(16|sh)?|sel|[su]sat(16)?|nop|pop|push|rfe([id][ab])?|" + "stm([id][ab])?|str(ex)?[bhd]?|(qd?)?sub|(sh?|q|u[qh]?)?sub(8|16)|" + "[su]xt(a?h|a?b(16)?)|srs([id][ab])?|swpb?|swi|smi|tst|teq|" + "wfe|wfi|yield" + ")" + "(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|hs|lo)?" + // condition codes
        "[sptrx]?" + // legal postfixes
        "(?=\\s)"
      }, COMMENT, hljs.QUOTE_STRING_MODE, {
        className: "string",
        begin: "'",
        end: "[^\\\\]'",
        relevance: 0
      }, {
        className: "title",
        begin: "\\|",
        end: "\\|",
        illegal: "\\n",
        relevance: 0
      }, {
        className: "number",
        variants: [ {
          // hex
          begin: "[#$=]?0x[0-9a-f]+"
        }, {
          // bin
          begin: "[#$=]?0b[01]+"
        }, {
          // literal
          begin: "[#$=]\\d+"
        }, {
          // bare number
          begin: "\\b\\d+"
        } ],
        relevance: 0
      }, {
        className: "symbol",
        variants: [ {
          // GNU ARM syntax
          begin: "^[ \\t]*[a-z_\\.\\$][a-z0-9_\\.\\$]+:"
        }, {
          // ARM syntax
          begin: "^[a-z_\\.\\$][a-z0-9_\\.\\$]+"
        }, {
          // label reference
          begin: "[=#]\\w+"
        } ],
        relevance: 0
      } ]
    };
  }
  var armasm_1 = armasm;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$1(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function lookahead(re) {
    return concat$1("(?=", re, ")");
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function optional(re) {
    return concat$1("(", re, ")?");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$1(...args) {
    const joined = args.map((x => source$1(x))).join("");
    return joined;
  }
  /**
   * Any of the passed expresssions may match
   *
   * Creates a huge this | this | that | that match
   * @param {(RegExp | string)[] } args
   * @returns {string}
   */  function either(...args) {
    const joined = "(" + args.map((x => source$1(x))).join("|") + ")";
    return joined;
  }
  /*
  Language: HTML, XML
  Website: https://www.w3.org/XML/
  Category: common
  */
  /** @type LanguageFn */  function xml(hljs) {
    // Element names can contain letters, digits, hyphens, underscores, and periods
    const TAG_NAME_RE = concat$1(/[A-Z_]/, optional(/[A-Z0-9_.-]+:/), /[A-Z0-9_.-]*/);
    const XML_IDENT_RE = "[A-Za-z0-9\\._:-]+";
    const XML_ENTITIES = {
      className: "symbol",
      begin: "&[a-z]+;|&#[0-9]+;|&#x[a-f0-9]+;"
    };
    const XML_META_KEYWORDS = {
      begin: "\\s",
      contains: [ {
        className: "meta-keyword",
        begin: "#?[a-z_][a-z1-9_-]+",
        illegal: "\\n"
      } ]
    };
    const XML_META_PAR_KEYWORDS = hljs.inherit(XML_META_KEYWORDS, {
      begin: "\\(",
      end: "\\)"
    });
    const APOS_META_STRING_MODE = hljs.inherit(hljs.APOS_STRING_MODE, {
      className: "meta-string"
    });
    const QUOTE_META_STRING_MODE = hljs.inherit(hljs.QUOTE_STRING_MODE, {
      className: "meta-string"
    });
    const TAG_INTERNALS = {
      endsWithParent: true,
      illegal: /</,
      relevance: 0,
      contains: [ {
        className: "attr",
        begin: XML_IDENT_RE,
        relevance: 0
      }, {
        begin: /=\s*/,
        relevance: 0,
        contains: [ {
          className: "string",
          endsParent: true,
          variants: [ {
            begin: /"/,
            end: /"/,
            contains: [ XML_ENTITIES ]
          }, {
            begin: /'/,
            end: /'/,
            contains: [ XML_ENTITIES ]
          }, {
            begin: /[^\s"'=<>`]+/
          } ]
        } ]
      } ]
    };
    return {
      name: "HTML, XML",
      aliases: [ "html", "xhtml", "rss", "atom", "xjb", "xsd", "xsl", "plist", "wsf", "svg" ],
      case_insensitive: true,
      contains: [ {
        className: "meta",
        begin: "<![a-z]",
        end: ">",
        relevance: 10,
        contains: [ XML_META_KEYWORDS, QUOTE_META_STRING_MODE, APOS_META_STRING_MODE, XML_META_PAR_KEYWORDS, {
          begin: "\\[",
          end: "\\]",
          contains: [ {
            className: "meta",
            begin: "<![a-z]",
            end: ">",
            contains: [ XML_META_KEYWORDS, XML_META_PAR_KEYWORDS, QUOTE_META_STRING_MODE, APOS_META_STRING_MODE ]
          } ]
        } ]
      }, hljs.COMMENT("\x3c!--", "--\x3e", {
        relevance: 10
      }), {
        begin: "<!\\[CDATA\\[",
        end: "\\]\\]>",
        relevance: 10
      }, XML_ENTITIES, {
        className: "meta",
        begin: /<\?xml/,
        end: /\?>/,
        relevance: 10
      }, {
        className: "tag",
        /*
          The lookahead pattern (?=...) ensures that 'begin' only matches
          '<style' as a single word, followed by a whitespace or an
          ending braket. The '$' is needed for the lexeme to be recognized
          by hljs.subMode() that tests lexemes outside the stream.
          */
        begin: "<style(?=\\s|>)",
        end: ">",
        keywords: {
          name: "style"
        },
        contains: [ TAG_INTERNALS ],
        starts: {
          end: "</style>",
          returnEnd: true,
          subLanguage: [ "css", "xml" ]
        }
      }, {
        className: "tag",
        // See the comment in the <style tag about the lookahead pattern
        begin: "<script(?=\\s|>)",
        end: ">",
        keywords: {
          name: "script"
        },
        contains: [ TAG_INTERNALS ],
        starts: {
          end: /<\/script>/,
          returnEnd: true,
          subLanguage: [ "javascript", "handlebars", "xml" ]
        }
      }, 
      // we need this for now for jSX
      {
        className: "tag",
        begin: /<>|<\/>/
      }, 
      // open tag
      {
        className: "tag",
        begin: concat$1(/</, lookahead(concat$1(TAG_NAME_RE, 
        // <tag/>
        // <tag>
        // <tag ...
        either(/\/>/, />/, /\s/)))),
        end: /\/?>/,
        contains: [ {
          className: "name",
          begin: TAG_NAME_RE,
          relevance: 0,
          starts: TAG_INTERNALS
        } ]
      }, 
      // close tag
      {
        className: "tag",
        begin: concat$1(/<\//, lookahead(concat$1(TAG_NAME_RE, />/))),
        contains: [ {
          className: "name",
          begin: TAG_NAME_RE,
          relevance: 0
        }, {
          begin: />/,
          relevance: 0
        } ]
      } ]
    };
  }
  var xml_1 = xml;
  /*
  Language: AsciiDoc
  Requires: xml.js
  Author: Dan Allen <dan.j.allen@gmail.com>
  Website: http://asciidoc.org
  Description: A semantic, text-based document format that can be exported to HTML, DocBook and other backends.
  Category: markup
  */
  /** @type LanguageFn */  function asciidoc(hljs) {
    return {
      name: "AsciiDoc",
      aliases: [ "adoc" ],
      contains: [ 
      // block comment
      hljs.COMMENT("^/{4,}\\n", "\\n/{4,}$", 
      // can also be done as...
      // '^/{4,}$',
      // '^/{4,}$',
      {
        relevance: 10
      }), 
      // line comment
      hljs.COMMENT("^//", "$", {
        relevance: 0
      }), 
      // title
      {
        className: "title",
        begin: "^\\.\\w.*$"
      }, 
      // example, admonition & sidebar blocks
      {
        begin: "^[=\\*]{4,}\\n",
        end: "\\n^[=\\*]{4,}$",
        relevance: 10
      }, 
      // headings
      {
        className: "section",
        relevance: 10,
        variants: [ {
          begin: "^(={1,5}) .+?( \\1)?$"
        }, {
          begin: "^[^\\[\\]\\n]+?\\n[=\\-~\\^\\+]{2,}$"
        } ]
      }, 
      // document attributes
      {
        className: "meta",
        begin: "^:.+?:",
        end: "\\s",
        excludeEnd: true,
        relevance: 10
      }, 
      // block attributes
      {
        className: "meta",
        begin: "^\\[.+?\\]$",
        relevance: 0
      }, 
      // quoteblocks
      {
        className: "quote",
        begin: "^_{4,}\\n",
        end: "\\n_{4,}$",
        relevance: 10
      }, 
      // listing and literal blocks
      {
        className: "code",
        begin: "^[\\-\\.]{4,}\\n",
        end: "\\n[\\-\\.]{4,}$",
        relevance: 10
      }, 
      // passthrough blocks
      {
        begin: "^\\+{4,}\\n",
        end: "\\n\\+{4,}$",
        contains: [ {
          begin: "<",
          end: ">",
          subLanguage: "xml",
          relevance: 0
        } ],
        relevance: 10
      }, 
      // lists (can only capture indicators)
      {
        className: "bullet",
        begin: "^(\\*+|-+|\\.+|[^\\n]+?::)\\s+"
      }, 
      // admonition
      {
        className: "symbol",
        begin: "^(NOTE|TIP|IMPORTANT|WARNING|CAUTION):\\s+",
        relevance: 10
      }, 
      // inline strong
      {
        className: "strong",
        // must not follow a word character or be followed by an asterisk or space
        begin: "\\B\\*(?![\\*\\s])",
        end: "(\\n{2}|\\*)",
        // allow escaped asterisk followed by word char
        contains: [ {
          begin: "\\\\*\\w",
          relevance: 0
        } ]
      }, 
      // inline emphasis
      {
        className: "emphasis",
        // must not follow a word character or be followed by a single quote or space
        begin: "\\B'(?!['\\s])",
        end: "(\\n{2}|')",
        // allow escaped single quote followed by word char
        contains: [ {
          begin: "\\\\'\\w",
          relevance: 0
        } ],
        relevance: 0
      }, 
      // inline emphasis (alt)
      {
        className: "emphasis",
        // must not follow a word character or be followed by an underline or space
        begin: "_(?![_\\s])",
        end: "(\\n{2}|_)",
        relevance: 0
      }, 
      // inline smart quotes
      {
        className: "string",
        variants: [ {
          begin: "``.+?''"
        }, {
          begin: "`.+?'"
        } ]
      }, 
      // inline code snippets (TODO should get same treatment as strong and emphasis)
      {
        className: "code",
        begin: "(`.+?`|\\+.+?\\+)",
        relevance: 0
      }, 
      // indented literal block
      {
        className: "code",
        begin: "^[ \\t]",
        end: "$",
        relevance: 0
      }, 
      // horizontal rules
      {
        begin: "^'{3,}[ \\t]*$",
        relevance: 10
      }, 
      // images and links
      {
        begin: "(link:)?(http|https|ftp|file|irc|image:?):\\S+?\\[[^[]*?\\]",
        returnBegin: true,
        contains: [ {
          begin: "(link|image:?):",
          relevance: 0
        }, {
          className: "link",
          begin: "\\w",
          end: "[^\\[]+",
          relevance: 0
        }, {
          className: "string",
          begin: "\\[",
          end: "\\]",
          excludeBegin: true,
          excludeEnd: true,
          relevance: 0
        } ],
        relevance: 10
      } ]
    };
  }
  var asciidoc_1 = asciidoc;
  /*
  Language: AVR Assembly
  Author: Vladimir Ermakov <vooon341@gmail.com>
  Category: assembler
  Website: https://www.microchip.com/webdoc/avrassembler/avrassembler.wb_instruction_list.html
  */
  /** @type LanguageFn */  function avrasm(hljs) {
    return {
      name: "AVR Assembly",
      case_insensitive: true,
      keywords: {
        $pattern: "\\.?" + hljs.IDENT_RE,
        keyword: 
        /* mnemonic */
        "adc add adiw and andi asr bclr bld brbc brbs brcc brcs break breq brge brhc brhs " + "brid brie brlo brlt brmi brne brpl brsh brtc brts brvc brvs bset bst call cbi cbr " + "clc clh cli cln clr cls clt clv clz com cp cpc cpi cpse dec eicall eijmp elpm eor " + "fmul fmuls fmulsu icall ijmp in inc jmp ld ldd ldi lds lpm lsl lsr mov movw mul " + "muls mulsu neg nop or ori out pop push rcall ret reti rjmp rol ror sbc sbr sbrc sbrs " + "sec seh sbi sbci sbic sbis sbiw sei sen ser ses set sev sez sleep spm st std sts sub " + "subi swap tst wdr",
        built_in: 
        /* general purpose registers */
        "r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 " + "r23 r24 r25 r26 r27 r28 r29 r30 r31 x|0 xh xl y|0 yh yl z|0 zh zl " + 
        /* IO Registers (ATMega128) */
        "ucsr1c udr1 ucsr1a ucsr1b ubrr1l ubrr1h ucsr0c ubrr0h tccr3c tccr3a tccr3b tcnt3h " + "tcnt3l ocr3ah ocr3al ocr3bh ocr3bl ocr3ch ocr3cl icr3h icr3l etimsk etifr tccr1c " + "ocr1ch ocr1cl twcr twdr twar twsr twbr osccal xmcra xmcrb eicra spmcsr spmcr portg " + "ddrg ping portf ddrf sreg sph spl xdiv rampz eicrb eimsk gimsk gicr eifr gifr timsk " + "tifr mcucr mcucsr tccr0 tcnt0 ocr0 assr tccr1a tccr1b tcnt1h tcnt1l ocr1ah ocr1al " + "ocr1bh ocr1bl icr1h icr1l tccr2 tcnt2 ocr2 ocdr wdtcr sfior eearh eearl eedr eecr " + "porta ddra pina portb ddrb pinb portc ddrc pinc portd ddrd pind spdr spsr spcr udr0 " + "ucsr0a ucsr0b ubrr0l acsr admux adcsr adch adcl porte ddre pine pinf",
        meta: ".byte .cseg .db .def .device .dseg .dw .endmacro .equ .eseg .exit .include .list " + ".listmac .macro .nolist .org .set"
      },
      contains: [ hljs.C_BLOCK_COMMENT_MODE, hljs.COMMENT(";", "$", {
        relevance: 0
      }), hljs.C_NUMBER_MODE, // 0x..., decimal, float
      hljs.BINARY_NUMBER_MODE, // 0b...
      {
        className: "number",
        begin: "\\b(\\$[a-zA-Z0-9]+|0o[0-7]+)"
      }, hljs.QUOTE_STRING_MODE, {
        className: "string",
        begin: "'",
        end: "[^\\\\]'",
        illegal: "[^\\\\][^']"
      }, {
        className: "symbol",
        begin: "^[A-Za-z0-9_.$]+:"
      }, {
        className: "meta",
        begin: "#",
        end: "$"
      }, {
        // substitution within a macro
        className: "subst",
        begin: "@[0-9]+"
      } ]
    };
  }
  var avrasm_1 = avrasm;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$2(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$2(...args) {
    const joined = args.map((x => source$2(x))).join("");
    return joined;
  }
  /*
  Language: Bash
  Author: vah <vahtenberg@gmail.com>
  Contributrors: Benjamin Pannell <contact@sierrasoftworks.com>
  Website: https://www.gnu.org/software/bash/
  Category: common
  */
  /** @type LanguageFn */  function bash(hljs) {
    const VAR = {};
    const BRACED_VAR = {
      begin: /\$\{/,
      end: /\}/,
      contains: [ "self", {
        begin: /:-/,
        contains: [ VAR ]
      } ]
    };
    Object.assign(VAR, {
      className: "variable",
      variants: [ {
        begin: concat$2(/\$[\w\d#@][\w\d_]*/, 
        // negative look-ahead tries to avoid matching patterns that are not
        // Perl at all like $ident$, @ident@, etc.
        `(?![\\w\\d])(?![$])`)
      }, BRACED_VAR ]
    });
    const SUBST = {
      className: "subst",
      begin: /\$\(/,
      end: /\)/,
      contains: [ hljs.BACKSLASH_ESCAPE ]
    };
    const HERE_DOC = {
      begin: /<<-?\s*(?=\w+)/,
      starts: {
        contains: [ hljs.END_SAME_AS_BEGIN({
          begin: /(\w+)/,
          end: /(\w+)/,
          className: "string"
        }) ]
      }
    };
    const QUOTE_STRING = {
      className: "string",
      begin: /"/,
      end: /"/,
      contains: [ hljs.BACKSLASH_ESCAPE, VAR, SUBST ]
    };
    SUBST.contains.push(QUOTE_STRING);
    const ESCAPED_QUOTE = {
      className: "",
      begin: /\\"/
    };
    const APOS_STRING = {
      className: "string",
      begin: /'/,
      end: /'/
    };
    const ARITHMETIC = {
      begin: /\$\(\(/,
      end: /\)\)/,
      contains: [ {
        begin: /\d+#[0-9a-f]+/,
        className: "number"
      }, hljs.NUMBER_MODE, VAR ]
    };
    const SH_LIKE_SHELLS = [ "fish", "bash", "zsh", "sh", "csh", "ksh", "tcsh", "dash", "scsh" ];
    const KNOWN_SHEBANG = hljs.SHEBANG({
      binary: `(${SH_LIKE_SHELLS.join("|")})`,
      relevance: 10
    });
    const FUNCTION = {
      className: "function",
      begin: /\w[\w\d_]*\s*\(\s*\)\s*\{/,
      returnBegin: true,
      contains: [ hljs.inherit(hljs.TITLE_MODE, {
        begin: /\w[\w\d_]*/
      }) ],
      relevance: 0
    };
    return {
      name: "Bash",
      aliases: [ "sh", "zsh" ],
      keywords: {
        $pattern: /\b[a-z._-]+\b/,
        keyword: "if then else elif fi for while in do done case esac function",
        literal: "true false",
        built_in: 
        // Shell built-ins
        // http://www.gnu.org/software/bash/manual/html_node/Shell-Builtin-Commands.html
        "break cd continue eval exec exit export getopts hash pwd readonly return shift test times " + "trap umask unset " + 
        // Bash built-ins
        "alias bind builtin caller command declare echo enable help let local logout mapfile printf " + "read readarray source type typeset ulimit unalias " + 
        // Shell modifiers
        "set shopt " + 
        // Zsh built-ins
        "autoload bg bindkey bye cap chdir clone comparguments compcall compctl compdescribe compfiles " + "compgroups compquote comptags comptry compvalues dirs disable disown echotc echoti emulate " + "fc fg float functions getcap getln history integer jobs kill limit log noglob popd print " + "pushd pushln rehash sched setcap setopt stat suspend ttyctl unfunction unhash unlimit " + "unsetopt vared wait whence where which zcompile zformat zftp zle zmodload zparseopts zprof " + "zpty zregexparse zsocket zstyle ztcp"
      },
      contains: [ KNOWN_SHEBANG, // to catch known shells and boost relevancy
      hljs.SHEBANG(), // to catch unknown shells but still highlight the shebang
      FUNCTION, ARITHMETIC, hljs.HASH_COMMENT_MODE, HERE_DOC, QUOTE_STRING, ESCAPED_QUOTE, APOS_STRING, VAR ]
    };
  }
  var bash_1 = bash;
  /*
  Language: Clojure
  Description: Clojure syntax (based on lisp.js)
  Author: mfornos
  Website: https://clojure.org
  Category: lisp
  */
  /** @type LanguageFn */  function clojure(hljs) {
    var SYMBOLSTART = "a-zA-Z_\\-!.?+*=<>&#'";
    var SYMBOL_RE = "[" + SYMBOLSTART + "][" + SYMBOLSTART + "0-9/;:]*";
    var globals = "def defonce defprotocol defstruct defmulti defmethod defn- defn defmacro deftype defrecord";
    var keywords = {
      $pattern: SYMBOL_RE,
      "builtin-name": 
      // Clojure keywords
      globals + " " + "cond apply if-not if-let if not not= =|0 <|0 >|0 <=|0 >=|0 ==|0 +|0 /|0 *|0 -|0 rem " + "quot neg? pos? delay? symbol? keyword? true? false? integer? empty? coll? list? " + "set? ifn? fn? associative? sequential? sorted? counted? reversible? number? decimal? " + "class? distinct? isa? float? rational? reduced? ratio? odd? even? char? seq? vector? " + "string? map? nil? contains? zero? instance? not-every? not-any? libspec? -> ->> .. . " + "inc compare do dotimes mapcat take remove take-while drop letfn drop-last take-last " + "drop-while while intern condp case reduced cycle split-at split-with repeat replicate " + "iterate range merge zipmap declare line-seq sort comparator sort-by dorun doall nthnext " + "nthrest partition eval doseq await await-for let agent atom send send-off release-pending-sends " + "add-watch mapv filterv remove-watch agent-error restart-agent set-error-handler error-handler " + "set-error-mode! error-mode shutdown-agents quote var fn loop recur throw try monitor-enter " + "monitor-exit macroexpand macroexpand-1 for dosync and or " + "when when-not when-let comp juxt partial sequence memoize constantly complement identity assert " + "peek pop doto proxy first rest cons cast coll last butlast " + "sigs reify second ffirst fnext nfirst nnext meta with-meta ns in-ns create-ns import " + "refer keys select-keys vals key val rseq name namespace promise into transient persistent! conj! " + "assoc! dissoc! pop! disj! use class type num float double short byte boolean bigint biginteger " + "bigdec print-method print-dup throw-if printf format load compile get-in update-in pr pr-on newline " + "flush read slurp read-line subvec with-open memfn time re-find re-groups rand-int rand mod locking " + "assert-valid-fdecl alias resolve ref deref refset swap! reset! set-validator! compare-and-set! alter-meta! " + "reset-meta! commute get-validator alter ref-set ref-history-count ref-min-history ref-max-history ensure sync io! " + "new next conj set! to-array future future-call into-array aset gen-class reduce map filter find empty " + "hash-map hash-set sorted-map sorted-map-by sorted-set sorted-set-by vec vector seq flatten reverse assoc dissoc list " + "disj get union difference intersection extend extend-type extend-protocol int nth delay count concat chunk chunk-buffer " + "chunk-append chunk-first chunk-rest max min dec unchecked-inc-int unchecked-inc unchecked-dec-inc unchecked-dec unchecked-negate " + "unchecked-add-int unchecked-add unchecked-subtract-int unchecked-subtract chunk-next chunk-cons chunked-seq? prn vary-meta " + "lazy-seq spread list* str find-keyword keyword symbol gensym force rationalize"
    };
    var SIMPLE_NUMBER_RE = "[-+]?\\d+(\\.\\d+)?";
    var SYMBOL = {
      begin: SYMBOL_RE,
      relevance: 0
    };
    var NUMBER = {
      className: "number",
      begin: SIMPLE_NUMBER_RE,
      relevance: 0
    };
    var STRING = hljs.inherit(hljs.QUOTE_STRING_MODE, {
      illegal: null
    });
    var COMMENT = hljs.COMMENT(";", "$", {
      relevance: 0
    });
    var LITERAL = {
      className: "literal",
      begin: /\b(true|false|nil)\b/
    };
    var COLLECTION = {
      begin: "[\\[\\{]",
      end: "[\\]\\}]"
    };
    var HINT = {
      className: "comment",
      begin: "\\^" + SYMBOL_RE
    };
    var HINT_COL = hljs.COMMENT("\\^\\{", "\\}");
    var KEY = {
      className: "symbol",
      begin: "[:]{1,2}" + SYMBOL_RE
    };
    var LIST = {
      begin: "\\(",
      end: "\\)"
    };
    var BODY = {
      endsWithParent: true,
      relevance: 0
    };
    var NAME = {
      keywords: keywords,
      className: "name",
      begin: SYMBOL_RE,
      relevance: 0,
      starts: BODY
    };
    var DEFAULT_CONTAINS = [ LIST, STRING, HINT, HINT_COL, COMMENT, KEY, COLLECTION, NUMBER, LITERAL, SYMBOL ];
    var GLOBAL = {
      beginKeywords: globals,
      lexemes: SYMBOL_RE,
      end: '(\\[|#|\\d|"|:|\\{|\\)|\\(|$)',
      contains: [ {
        className: "title",
        begin: SYMBOL_RE,
        relevance: 0,
        excludeEnd: true,
        // we can only have a single title
        endsParent: true
      } ].concat(DEFAULT_CONTAINS)
    };
    LIST.contains = [ hljs.COMMENT("comment", ""), GLOBAL, NAME, BODY ];
    BODY.contains = DEFAULT_CONTAINS;
    COLLECTION.contains = DEFAULT_CONTAINS;
    HINT_COL.contains = [ COLLECTION ];
    return {
      name: "Clojure",
      aliases: [ "clj" ],
      illegal: /\S/,
      contains: [ LIST, STRING, HINT, HINT_COL, COMMENT, KEY, COLLECTION, NUMBER, LITERAL ]
    };
  }
  var clojure_1 = clojure;
  /*
  Language: CMake
  Description: CMake is an open-source cross-platform system for build automation.
  Author: Igor Kalnitsky <igor@kalnitsky.org>
  Website: https://cmake.org
  */
  /** @type LanguageFn */  function cmake(hljs) {
    return {
      name: "CMake",
      aliases: [ "cmake.in" ],
      case_insensitive: true,
      keywords: {
        keyword: 
        // scripting commands
        "break cmake_host_system_information cmake_minimum_required cmake_parse_arguments " + "cmake_policy configure_file continue elseif else endforeach endfunction endif endmacro " + "endwhile execute_process file find_file find_library find_package find_path " + "find_program foreach function get_cmake_property get_directory_property " + "get_filename_component get_property if include include_guard list macro " + "mark_as_advanced math message option return separate_arguments " + "set_directory_properties set_property set site_name string unset variable_watch while " + 
        // project commands
        "add_compile_definitions add_compile_options add_custom_command add_custom_target " + "add_definitions add_dependencies add_executable add_library add_link_options " + "add_subdirectory add_test aux_source_directory build_command create_test_sourcelist " + "define_property enable_language enable_testing export fltk_wrap_ui " + "get_source_file_property get_target_property get_test_property include_directories " + "include_external_msproject include_regular_expression install link_directories " + "link_libraries load_cache project qt_wrap_cpp qt_wrap_ui remove_definitions " + "set_source_files_properties set_target_properties set_tests_properties source_group " + "target_compile_definitions target_compile_features target_compile_options " + "target_include_directories target_link_directories target_link_libraries " + "target_link_options target_sources try_compile try_run " + 
        // CTest commands
        "ctest_build ctest_configure ctest_coverage ctest_empty_binary_directory ctest_memcheck " + "ctest_read_custom_files ctest_run_script ctest_sleep ctest_start ctest_submit " + "ctest_test ctest_update ctest_upload " + 
        // deprecated commands
        "build_name exec_program export_library_dependencies install_files install_programs " + "install_targets load_command make_directory output_required_files remove " + "subdir_depends subdirs use_mangled_mesa utility_source variable_requires write_file " + "qt5_use_modules qt5_use_package qt5_wrap_cpp " + 
        // core keywords
        "on off true false and or not command policy target test exists is_newer_than " + "is_directory is_symlink is_absolute matches less greater equal less_equal " + "greater_equal strless strgreater strequal strless_equal strgreater_equal version_less " + "version_greater version_equal version_less_equal version_greater_equal in_list defined"
      },
      contains: [ {
        className: "variable",
        begin: /\$\{/,
        end: /\}/
      }, hljs.HASH_COMMENT_MODE, hljs.QUOTE_STRING_MODE, hljs.NUMBER_MODE ]
    };
  }
  var cmake_1 = cmake;
  const KEYWORDS = [ "as", // for exports
  "in", "of", "if", "for", "while", "finally", "var", "new", "function", "do", "return", "void", "else", "break", "catch", "instanceof", "with", "throw", "case", "default", "try", "switch", "continue", "typeof", "delete", "let", "yield", "const", "class", 
  // JS handles these with a special rule
  // "get",
  // "set",
  "debugger", "async", "await", "static", "import", "from", "export", "extends" ];
  const LITERALS = [ "true", "false", "null", "undefined", "NaN", "Infinity" ];
  const TYPES = [ "Intl", "DataView", "Number", "Math", "Date", "String", "RegExp", "Object", "Function", "Boolean", "Error", "Symbol", "Set", "Map", "WeakSet", "WeakMap", "Proxy", "Reflect", "JSON", "Promise", "Float64Array", "Int16Array", "Int32Array", "Int8Array", "Uint16Array", "Uint32Array", "Float32Array", "Array", "Uint8Array", "Uint8ClampedArray", "ArrayBuffer" ];
  const ERROR_TYPES = [ "EvalError", "InternalError", "RangeError", "ReferenceError", "SyntaxError", "TypeError", "URIError" ];
  const BUILT_IN_GLOBALS = [ "setInterval", "setTimeout", "clearInterval", "clearTimeout", "require", "exports", "eval", "isFinite", "isNaN", "parseFloat", "parseInt", "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent", "escape", "unescape" ];
  const BUILT_IN_VARIABLES = [ "arguments", "this", "super", "console", "window", "document", "localStorage", "module", "global" ];
  const BUILT_INS = [].concat(BUILT_IN_GLOBALS, BUILT_IN_VARIABLES, TYPES, ERROR_TYPES);
  /*
  Language: CoffeeScript
  Author: Dmytrii Nagirniak <dnagir@gmail.com>
  Contributors: Oleg Efimov <efimovov@gmail.com>, Cédric Néhémie <cedric.nehemie@gmail.com>
  Description: CoffeeScript is a programming language that transcompiles to JavaScript. For info about language see http://coffeescript.org/
  Category: common, scripting
  Website: https://coffeescript.org
  */
  /** @type LanguageFn */  function coffeescript(hljs) {
    const COFFEE_BUILT_INS = [ "npm", "print" ];
    const COFFEE_LITERALS = [ "yes", "no", "on", "off" ];
    const COFFEE_KEYWORDS = [ "then", "unless", "until", "loop", "by", "when", "and", "or", "is", "isnt", "not" ];
    const NOT_VALID_KEYWORDS = [ "var", "const", "let", "function", "static" ];
    const excluding = list => kw => !list.includes(kw);
    const KEYWORDS$1 = {
      keyword: KEYWORDS.concat(COFFEE_KEYWORDS).filter(excluding(NOT_VALID_KEYWORDS)).join(" "),
      literal: LITERALS.concat(COFFEE_LITERALS).join(" "),
      built_in: BUILT_INS.concat(COFFEE_BUILT_INS).join(" ")
    };
    const JS_IDENT_RE = "[A-Za-z$_][0-9A-Za-z$_]*";
    const SUBST = {
      className: "subst",
      begin: /#\{/,
      end: /\}/,
      keywords: KEYWORDS$1
    };
    const EXPRESSIONS = [ hljs.BINARY_NUMBER_MODE, hljs.inherit(hljs.C_NUMBER_MODE, {
      starts: {
        end: "(\\s*/)?",
        relevance: 0
      }
    }), // a number tries to eat the following slash to prevent treating it as a regexp
    {
      className: "string",
      variants: [ {
        begin: /'''/,
        end: /'''/,
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: /'/,
        end: /'/,
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: /"""/,
        end: /"""/,
        contains: [ hljs.BACKSLASH_ESCAPE, SUBST ]
      }, {
        begin: /"/,
        end: /"/,
        contains: [ hljs.BACKSLASH_ESCAPE, SUBST ]
      } ]
    }, {
      className: "regexp",
      variants: [ {
        begin: "///",
        end: "///",
        contains: [ SUBST, hljs.HASH_COMMENT_MODE ]
      }, {
        begin: "//[gim]{0,3}(?=\\W)",
        relevance: 0
      }, {
        // regex can't start with space to parse x / 2 / 3 as two divisions
        // regex can't start with *, and it supports an "illegal" in the main mode
        begin: /\/(?![ *]).*?(?![\\]).\/[gim]{0,3}(?=\W)/
      } ]
    }, {
      begin: "@" + JS_IDENT_RE
    }, {
      subLanguage: "javascript",
      excludeBegin: true,
      excludeEnd: true,
      variants: [ {
        begin: "```",
        end: "```"
      }, {
        begin: "`",
        end: "`"
      } ]
    } ];
    SUBST.contains = EXPRESSIONS;
    const TITLE = hljs.inherit(hljs.TITLE_MODE, {
      begin: JS_IDENT_RE
    });
    const POSSIBLE_PARAMS_RE = "(\\(.*\\)\\s*)?\\B[-=]>";
    const PARAMS = {
      className: "params",
      begin: "\\([^\\(]",
      returnBegin: true,
      /* We need another contained nameless mode to not have every nested
      pair of parens to be called "params" */
      contains: [ {
        begin: /\(/,
        end: /\)/,
        keywords: KEYWORDS$1,
        contains: [ "self" ].concat(EXPRESSIONS)
      } ]
    };
    return {
      name: "CoffeeScript",
      aliases: [ "coffee", "cson", "iced" ],
      keywords: KEYWORDS$1,
      illegal: /\/\*/,
      contains: EXPRESSIONS.concat([ hljs.COMMENT("###", "###"), hljs.HASH_COMMENT_MODE, {
        className: "function",
        begin: "^\\s*" + JS_IDENT_RE + "\\s*=\\s*" + POSSIBLE_PARAMS_RE,
        end: "[-=]>",
        returnBegin: true,
        contains: [ TITLE, PARAMS ]
      }, {
        // anonymous function start
        begin: /[:\(,=]\s*/,
        relevance: 0,
        contains: [ {
          className: "function",
          begin: POSSIBLE_PARAMS_RE,
          end: "[-=]>",
          returnBegin: true,
          contains: [ PARAMS ]
        } ]
      }, {
        className: "class",
        beginKeywords: "class",
        end: "$",
        illegal: /[:="\[\]]/,
        contains: [ {
          beginKeywords: "extends",
          endsWithParent: true,
          illegal: /[:="\[\]]/,
          contains: [ TITLE ]
        }, TITLE ]
      }, {
        begin: JS_IDENT_RE + ":",
        end: ":",
        returnBegin: true,
        returnEnd: true,
        relevance: 0
      } ])
    };
  }
  var coffeescript_1 = coffeescript;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$3(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function optional$1(re) {
    return concat$3("(", re, ")?");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$3(...args) {
    const joined = args.map((x => source$3(x))).join("");
    return joined;
  }
  /*
  Language: C-like foundation grammar for C/C++ grammars
  Author: Ivan Sagalaev <maniac@softwaremaniacs.org>
  Contributors: Evgeny Stepanischev <imbolk@gmail.com>, Zaven Muradyan <megalivoithos@gmail.com>, Roel Deckers <admin@codingcat.nl>, Sam Wu <samsam2310@gmail.com>, Jordi Petit <jordi.petit@gmail.com>, Pieter Vantorre <pietervantorre@gmail.com>, Google Inc. (David Benjamin) <davidben@google.com>
  */
  /** @type LanguageFn */  function cLike(hljs) {
    // added for historic reasons because `hljs.C_LINE_COMMENT_MODE` does
    // not include such support nor can we be sure all the grammars depending
    // on it would desire this behavior
    const C_LINE_COMMENT_MODE = hljs.COMMENT("//", "$", {
      contains: [ {
        begin: /\\\n/
      } ]
    });
    const DECLTYPE_AUTO_RE = "decltype\\(auto\\)";
    const NAMESPACE_RE = "[a-zA-Z_]\\w*::";
    const TEMPLATE_ARGUMENT_RE = "<[^<>]+>";
    const FUNCTION_TYPE_RE = "(" + DECLTYPE_AUTO_RE + "|" + optional$1(NAMESPACE_RE) + "[a-zA-Z_]\\w*" + optional$1(TEMPLATE_ARGUMENT_RE) + ")";
    const CPP_PRIMITIVE_TYPES = {
      className: "keyword",
      begin: "\\b[a-z\\d_]*_t\\b"
    };
    // https://en.cppreference.com/w/cpp/language/escape
    // \\ \x \xFF \u2837 \u00323747 \374
        const CHARACTER_ESCAPES = "\\\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4,8}|[0-7]{3}|\\S)";
    const STRINGS = {
      className: "string",
      variants: [ {
        begin: '(u8?|U|L)?"',
        end: '"',
        illegal: "\\n",
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: "(u8?|U|L)?'(" + CHARACTER_ESCAPES + "|.)",
        end: "'",
        illegal: "."
      }, hljs.END_SAME_AS_BEGIN({
        begin: /(?:u8?|U|L)?R"([^()\\ ]{0,16})\(/,
        end: /\)([^()\\ ]{0,16})"/
      }) ]
    };
    const NUMBERS = {
      className: "number",
      variants: [ {
        begin: "\\b(0b[01']+)"
      }, {
        begin: "(-?)\\b([\\d']+(\\.[\\d']*)?|\\.[\\d']+)(u|U|l|L|ul|UL|f|F|b|B)"
      }, {
        begin: "(-?)(\\b0[xX][a-fA-F0-9']+|(\\b[\\d']+(\\.[\\d']*)?|\\.[\\d']+)([eE][-+]?[\\d']+)?)"
      } ],
      relevance: 0
    };
    const PREPROCESSOR = {
      className: "meta",
      begin: /#\s*[a-z]+\b/,
      end: /$/,
      keywords: {
        "meta-keyword": "if else elif endif define undef warning error line " + "pragma _Pragma ifdef ifndef include"
      },
      contains: [ {
        begin: /\\\n/,
        relevance: 0
      }, hljs.inherit(STRINGS, {
        className: "meta-string"
      }), {
        className: "meta-string",
        begin: /<.*?>/,
        end: /$/,
        illegal: "\\n"
      }, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE ]
    };
    const TITLE_MODE = {
      className: "title",
      begin: optional$1(NAMESPACE_RE) + hljs.IDENT_RE,
      relevance: 0
    };
    const FUNCTION_TITLE = optional$1(NAMESPACE_RE) + hljs.IDENT_RE + "\\s*\\(";
    const CPP_KEYWORDS = {
      keyword: "int float while private char char8_t char16_t char32_t catch import module export virtual operator sizeof " + "dynamic_cast|10 typedef const_cast|10 const for static_cast|10 union namespace " + "unsigned long volatile static protected bool template mutable if public friend " + "do goto auto void enum else break extern using asm case typeid wchar_t " + "short reinterpret_cast|10 default double register explicit signed typename try this " + "switch continue inline delete alignas alignof constexpr consteval constinit decltype " + "concept co_await co_return co_yield requires " + "noexcept static_assert thread_local restrict final override " + "atomic_bool atomic_char atomic_schar " + "atomic_uchar atomic_short atomic_ushort atomic_int atomic_uint atomic_long atomic_ulong atomic_llong " + "atomic_ullong new throw return " + "and and_eq bitand bitor compl not not_eq or or_eq xor xor_eq",
      built_in: "std string wstring cin cout cerr clog stdin stdout stderr stringstream istringstream ostringstream " + "auto_ptr deque list queue stack vector map set pair bitset multiset multimap unordered_set " + "unordered_map unordered_multiset unordered_multimap priority_queue make_pair array shared_ptr abort terminate abs acos " + "asin atan2 atan calloc ceil cosh cos exit exp fabs floor fmod fprintf fputs free frexp " + "fscanf future isalnum isalpha iscntrl isdigit isgraph islower isprint ispunct isspace isupper " + "isxdigit tolower toupper labs ldexp log10 log malloc realloc memchr memcmp memcpy memset modf pow " + "printf putchar puts scanf sinh sin snprintf sprintf sqrt sscanf strcat strchr strcmp " + "strcpy strcspn strlen strncat strncmp strncpy strpbrk strrchr strspn strstr tanh tan " + "vfprintf vprintf vsprintf endl initializer_list unique_ptr _Bool complex _Complex imaginary _Imaginary",
      literal: "true false nullptr NULL"
    };
    const EXPRESSION_CONTAINS = [ PREPROCESSOR, CPP_PRIMITIVE_TYPES, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, NUMBERS, STRINGS ];
    const EXPRESSION_CONTEXT = {
      // This mode covers expression context where we can't expect a function
      // definition and shouldn't highlight anything that looks like one:
      // `return some()`, `else if()`, `(x*sum(1, 2))`
      variants: [ {
        begin: /=/,
        end: /;/
      }, {
        begin: /\(/,
        end: /\)/
      }, {
        beginKeywords: "new throw return else",
        end: /;/
      } ],
      keywords: CPP_KEYWORDS,
      contains: EXPRESSION_CONTAINS.concat([ {
        begin: /\(/,
        end: /\)/,
        keywords: CPP_KEYWORDS,
        contains: EXPRESSION_CONTAINS.concat([ "self" ]),
        relevance: 0
      } ]),
      relevance: 0
    };
    const FUNCTION_DECLARATION = {
      className: "function",
      begin: "(" + FUNCTION_TYPE_RE + "[\\*&\\s]+)+" + FUNCTION_TITLE,
      returnBegin: true,
      end: /[{;=]/,
      excludeEnd: true,
      keywords: CPP_KEYWORDS,
      illegal: /[^\w\s\*&:<>]/,
      contains: [ {
        // to prevent it from being confused as the function title
        begin: DECLTYPE_AUTO_RE,
        keywords: CPP_KEYWORDS,
        relevance: 0
      }, {
        begin: FUNCTION_TITLE,
        returnBegin: true,
        contains: [ TITLE_MODE ],
        relevance: 0
      }, {
        className: "params",
        begin: /\(/,
        end: /\)/,
        keywords: CPP_KEYWORDS,
        relevance: 0,
        contains: [ C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, STRINGS, NUMBERS, CPP_PRIMITIVE_TYPES, 
        // Count matching parentheses.
        {
          begin: /\(/,
          end: /\)/,
          keywords: CPP_KEYWORDS,
          relevance: 0,
          contains: [ "self", C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, STRINGS, NUMBERS, CPP_PRIMITIVE_TYPES ]
        } ]
      }, CPP_PRIMITIVE_TYPES, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, PREPROCESSOR ]
    };
    return {
      aliases: [ "c", "cc", "h", "c++", "h++", "hpp", "hh", "hxx", "cxx" ],
      keywords: CPP_KEYWORDS,
      // the base c-like language will NEVER be auto-detected, rather the
      // derivitives: c, c++, arduino turn auto-detect back on for themselves
      disableAutodetect: true,
      illegal: "</",
      contains: [].concat(EXPRESSION_CONTEXT, FUNCTION_DECLARATION, EXPRESSION_CONTAINS, [ PREPROCESSOR, {
        // containers: ie, `vector <int> rooms (9);`
        begin: "\\b(deque|list|queue|priority_queue|pair|stack|vector|map|set|bitset|multiset|multimap|unordered_map|unordered_set|unordered_multiset|unordered_multimap|array)\\s*<",
        end: ">",
        keywords: CPP_KEYWORDS,
        contains: [ "self", CPP_PRIMITIVE_TYPES ]
      }, {
        begin: hljs.IDENT_RE + "::",
        keywords: CPP_KEYWORDS
      }, {
        className: "class",
        beginKeywords: "enum class struct union",
        end: /[{;:<>=]/,
        contains: [ {
          beginKeywords: "final class struct"
        }, hljs.TITLE_MODE ]
      } ]),
      exports: {
        preprocessor: PREPROCESSOR,
        strings: STRINGS,
        keywords: CPP_KEYWORDS
      }
    };
  }
  var cLike_1 = cLike;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$4(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function optional$2(re) {
    return concat$4("(", re, ")?");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$4(...args) {
    const joined = args.map((x => source$4(x))).join("");
    return joined;
  }
  /*
  Language: C-like foundation grammar for C/C++ grammars
  Author: Ivan Sagalaev <maniac@softwaremaniacs.org>
  Contributors: Evgeny Stepanischev <imbolk@gmail.com>, Zaven Muradyan <megalivoithos@gmail.com>, Roel Deckers <admin@codingcat.nl>, Sam Wu <samsam2310@gmail.com>, Jordi Petit <jordi.petit@gmail.com>, Pieter Vantorre <pietervantorre@gmail.com>, Google Inc. (David Benjamin) <davidben@google.com>
  */
  /** @type LanguageFn */  function cLike$1(hljs) {
    // added for historic reasons because `hljs.C_LINE_COMMENT_MODE` does
    // not include such support nor can we be sure all the grammars depending
    // on it would desire this behavior
    const C_LINE_COMMENT_MODE = hljs.COMMENT("//", "$", {
      contains: [ {
        begin: /\\\n/
      } ]
    });
    const DECLTYPE_AUTO_RE = "decltype\\(auto\\)";
    const NAMESPACE_RE = "[a-zA-Z_]\\w*::";
    const TEMPLATE_ARGUMENT_RE = "<[^<>]+>";
    const FUNCTION_TYPE_RE = "(" + DECLTYPE_AUTO_RE + "|" + optional$2(NAMESPACE_RE) + "[a-zA-Z_]\\w*" + optional$2(TEMPLATE_ARGUMENT_RE) + ")";
    const CPP_PRIMITIVE_TYPES = {
      className: "keyword",
      begin: "\\b[a-z\\d_]*_t\\b"
    };
    // https://en.cppreference.com/w/cpp/language/escape
    // \\ \x \xFF \u2837 \u00323747 \374
        const CHARACTER_ESCAPES = "\\\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4,8}|[0-7]{3}|\\S)";
    const STRINGS = {
      className: "string",
      variants: [ {
        begin: '(u8?|U|L)?"',
        end: '"',
        illegal: "\\n",
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: "(u8?|U|L)?'(" + CHARACTER_ESCAPES + "|.)",
        end: "'",
        illegal: "."
      }, hljs.END_SAME_AS_BEGIN({
        begin: /(?:u8?|U|L)?R"([^()\\ ]{0,16})\(/,
        end: /\)([^()\\ ]{0,16})"/
      }) ]
    };
    const NUMBERS = {
      className: "number",
      variants: [ {
        begin: "\\b(0b[01']+)"
      }, {
        begin: "(-?)\\b([\\d']+(\\.[\\d']*)?|\\.[\\d']+)(u|U|l|L|ul|UL|f|F|b|B)"
      }, {
        begin: "(-?)(\\b0[xX][a-fA-F0-9']+|(\\b[\\d']+(\\.[\\d']*)?|\\.[\\d']+)([eE][-+]?[\\d']+)?)"
      } ],
      relevance: 0
    };
    const PREPROCESSOR = {
      className: "meta",
      begin: /#\s*[a-z]+\b/,
      end: /$/,
      keywords: {
        "meta-keyword": "if else elif endif define undef warning error line " + "pragma _Pragma ifdef ifndef include"
      },
      contains: [ {
        begin: /\\\n/,
        relevance: 0
      }, hljs.inherit(STRINGS, {
        className: "meta-string"
      }), {
        className: "meta-string",
        begin: /<.*?>/,
        end: /$/,
        illegal: "\\n"
      }, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE ]
    };
    const TITLE_MODE = {
      className: "title",
      begin: optional$2(NAMESPACE_RE) + hljs.IDENT_RE,
      relevance: 0
    };
    const FUNCTION_TITLE = optional$2(NAMESPACE_RE) + hljs.IDENT_RE + "\\s*\\(";
    const CPP_KEYWORDS = {
      keyword: "int float while private char char8_t char16_t char32_t catch import module export virtual operator sizeof " + "dynamic_cast|10 typedef const_cast|10 const for static_cast|10 union namespace " + "unsigned long volatile static protected bool template mutable if public friend " + "do goto auto void enum else break extern using asm case typeid wchar_t " + "short reinterpret_cast|10 default double register explicit signed typename try this " + "switch continue inline delete alignas alignof constexpr consteval constinit decltype " + "concept co_await co_return co_yield requires " + "noexcept static_assert thread_local restrict final override " + "atomic_bool atomic_char atomic_schar " + "atomic_uchar atomic_short atomic_ushort atomic_int atomic_uint atomic_long atomic_ulong atomic_llong " + "atomic_ullong new throw return " + "and and_eq bitand bitor compl not not_eq or or_eq xor xor_eq",
      built_in: "std string wstring cin cout cerr clog stdin stdout stderr stringstream istringstream ostringstream " + "auto_ptr deque list queue stack vector map set pair bitset multiset multimap unordered_set " + "unordered_map unordered_multiset unordered_multimap priority_queue make_pair array shared_ptr abort terminate abs acos " + "asin atan2 atan calloc ceil cosh cos exit exp fabs floor fmod fprintf fputs free frexp " + "fscanf future isalnum isalpha iscntrl isdigit isgraph islower isprint ispunct isspace isupper " + "isxdigit tolower toupper labs ldexp log10 log malloc realloc memchr memcmp memcpy memset modf pow " + "printf putchar puts scanf sinh sin snprintf sprintf sqrt sscanf strcat strchr strcmp " + "strcpy strcspn strlen strncat strncmp strncpy strpbrk strrchr strspn strstr tanh tan " + "vfprintf vprintf vsprintf endl initializer_list unique_ptr _Bool complex _Complex imaginary _Imaginary",
      literal: "true false nullptr NULL"
    };
    const EXPRESSION_CONTAINS = [ PREPROCESSOR, CPP_PRIMITIVE_TYPES, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, NUMBERS, STRINGS ];
    const EXPRESSION_CONTEXT = {
      // This mode covers expression context where we can't expect a function
      // definition and shouldn't highlight anything that looks like one:
      // `return some()`, `else if()`, `(x*sum(1, 2))`
      variants: [ {
        begin: /=/,
        end: /;/
      }, {
        begin: /\(/,
        end: /\)/
      }, {
        beginKeywords: "new throw return else",
        end: /;/
      } ],
      keywords: CPP_KEYWORDS,
      contains: EXPRESSION_CONTAINS.concat([ {
        begin: /\(/,
        end: /\)/,
        keywords: CPP_KEYWORDS,
        contains: EXPRESSION_CONTAINS.concat([ "self" ]),
        relevance: 0
      } ]),
      relevance: 0
    };
    const FUNCTION_DECLARATION = {
      className: "function",
      begin: "(" + FUNCTION_TYPE_RE + "[\\*&\\s]+)+" + FUNCTION_TITLE,
      returnBegin: true,
      end: /[{;=]/,
      excludeEnd: true,
      keywords: CPP_KEYWORDS,
      illegal: /[^\w\s\*&:<>]/,
      contains: [ {
        // to prevent it from being confused as the function title
        begin: DECLTYPE_AUTO_RE,
        keywords: CPP_KEYWORDS,
        relevance: 0
      }, {
        begin: FUNCTION_TITLE,
        returnBegin: true,
        contains: [ TITLE_MODE ],
        relevance: 0
      }, {
        className: "params",
        begin: /\(/,
        end: /\)/,
        keywords: CPP_KEYWORDS,
        relevance: 0,
        contains: [ C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, STRINGS, NUMBERS, CPP_PRIMITIVE_TYPES, 
        // Count matching parentheses.
        {
          begin: /\(/,
          end: /\)/,
          keywords: CPP_KEYWORDS,
          relevance: 0,
          contains: [ "self", C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, STRINGS, NUMBERS, CPP_PRIMITIVE_TYPES ]
        } ]
      }, CPP_PRIMITIVE_TYPES, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, PREPROCESSOR ]
    };
    return {
      aliases: [ "c", "cc", "h", "c++", "h++", "hpp", "hh", "hxx", "cxx" ],
      keywords: CPP_KEYWORDS,
      // the base c-like language will NEVER be auto-detected, rather the
      // derivitives: c, c++, arduino turn auto-detect back on for themselves
      disableAutodetect: true,
      illegal: "</",
      contains: [].concat(EXPRESSION_CONTEXT, FUNCTION_DECLARATION, EXPRESSION_CONTAINS, [ PREPROCESSOR, {
        // containers: ie, `vector <int> rooms (9);`
        begin: "\\b(deque|list|queue|priority_queue|pair|stack|vector|map|set|bitset|multiset|multimap|unordered_map|unordered_set|unordered_multiset|unordered_multimap|array)\\s*<",
        end: ">",
        keywords: CPP_KEYWORDS,
        contains: [ "self", CPP_PRIMITIVE_TYPES ]
      }, {
        begin: hljs.IDENT_RE + "::",
        keywords: CPP_KEYWORDS
      }, {
        className: "class",
        beginKeywords: "enum class struct union",
        end: /[{;:<>=]/,
        contains: [ {
          beginKeywords: "final class struct"
        }, hljs.TITLE_MODE ]
      } ]),
      exports: {
        preprocessor: PREPROCESSOR,
        strings: STRINGS,
        keywords: CPP_KEYWORDS
      }
    };
  }
  /*
  Language: C
  Category: common, system
  Website: https://en.wikipedia.org/wiki/C_(programming_language)
  */
  /** @type LanguageFn */  function c(hljs) {
    const lang = cLike$1(hljs);
    // Until C is actually different than C++ there is no reason to auto-detect C
    // as it's own language since it would just fail auto-detect testing or
    // simply match with C++.
    
    // See further comments in c-like.js.
    // lang.disableAutodetect = false;
        lang.name = "C";
    lang.aliases = [ "c", "h" ];
    return lang;
  }
  var c_1 = c;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$5(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function optional$3(re) {
    return concat$5("(", re, ")?");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$5(...args) {
    const joined = args.map((x => source$5(x))).join("");
    return joined;
  }
  /*
  Language: C-like foundation grammar for C/C++ grammars
  Author: Ivan Sagalaev <maniac@softwaremaniacs.org>
  Contributors: Evgeny Stepanischev <imbolk@gmail.com>, Zaven Muradyan <megalivoithos@gmail.com>, Roel Deckers <admin@codingcat.nl>, Sam Wu <samsam2310@gmail.com>, Jordi Petit <jordi.petit@gmail.com>, Pieter Vantorre <pietervantorre@gmail.com>, Google Inc. (David Benjamin) <davidben@google.com>
  */
  /** @type LanguageFn */  function cLike$2(hljs) {
    // added for historic reasons because `hljs.C_LINE_COMMENT_MODE` does
    // not include such support nor can we be sure all the grammars depending
    // on it would desire this behavior
    const C_LINE_COMMENT_MODE = hljs.COMMENT("//", "$", {
      contains: [ {
        begin: /\\\n/
      } ]
    });
    const DECLTYPE_AUTO_RE = "decltype\\(auto\\)";
    const NAMESPACE_RE = "[a-zA-Z_]\\w*::";
    const TEMPLATE_ARGUMENT_RE = "<[^<>]+>";
    const FUNCTION_TYPE_RE = "(" + DECLTYPE_AUTO_RE + "|" + optional$3(NAMESPACE_RE) + "[a-zA-Z_]\\w*" + optional$3(TEMPLATE_ARGUMENT_RE) + ")";
    const CPP_PRIMITIVE_TYPES = {
      className: "keyword",
      begin: "\\b[a-z\\d_]*_t\\b"
    };
    // https://en.cppreference.com/w/cpp/language/escape
    // \\ \x \xFF \u2837 \u00323747 \374
        const CHARACTER_ESCAPES = "\\\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4,8}|[0-7]{3}|\\S)";
    const STRINGS = {
      className: "string",
      variants: [ {
        begin: '(u8?|U|L)?"',
        end: '"',
        illegal: "\\n",
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: "(u8?|U|L)?'(" + CHARACTER_ESCAPES + "|.)",
        end: "'",
        illegal: "."
      }, hljs.END_SAME_AS_BEGIN({
        begin: /(?:u8?|U|L)?R"([^()\\ ]{0,16})\(/,
        end: /\)([^()\\ ]{0,16})"/
      }) ]
    };
    const NUMBERS = {
      className: "number",
      variants: [ {
        begin: "\\b(0b[01']+)"
      }, {
        begin: "(-?)\\b([\\d']+(\\.[\\d']*)?|\\.[\\d']+)(u|U|l|L|ul|UL|f|F|b|B)"
      }, {
        begin: "(-?)(\\b0[xX][a-fA-F0-9']+|(\\b[\\d']+(\\.[\\d']*)?|\\.[\\d']+)([eE][-+]?[\\d']+)?)"
      } ],
      relevance: 0
    };
    const PREPROCESSOR = {
      className: "meta",
      begin: /#\s*[a-z]+\b/,
      end: /$/,
      keywords: {
        "meta-keyword": "if else elif endif define undef warning error line " + "pragma _Pragma ifdef ifndef include"
      },
      contains: [ {
        begin: /\\\n/,
        relevance: 0
      }, hljs.inherit(STRINGS, {
        className: "meta-string"
      }), {
        className: "meta-string",
        begin: /<.*?>/,
        end: /$/,
        illegal: "\\n"
      }, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE ]
    };
    const TITLE_MODE = {
      className: "title",
      begin: optional$3(NAMESPACE_RE) + hljs.IDENT_RE,
      relevance: 0
    };
    const FUNCTION_TITLE = optional$3(NAMESPACE_RE) + hljs.IDENT_RE + "\\s*\\(";
    const CPP_KEYWORDS = {
      keyword: "int float while private char char8_t char16_t char32_t catch import module export virtual operator sizeof " + "dynamic_cast|10 typedef const_cast|10 const for static_cast|10 union namespace " + "unsigned long volatile static protected bool template mutable if public friend " + "do goto auto void enum else break extern using asm case typeid wchar_t " + "short reinterpret_cast|10 default double register explicit signed typename try this " + "switch continue inline delete alignas alignof constexpr consteval constinit decltype " + "concept co_await co_return co_yield requires " + "noexcept static_assert thread_local restrict final override " + "atomic_bool atomic_char atomic_schar " + "atomic_uchar atomic_short atomic_ushort atomic_int atomic_uint atomic_long atomic_ulong atomic_llong " + "atomic_ullong new throw return " + "and and_eq bitand bitor compl not not_eq or or_eq xor xor_eq",
      built_in: "std string wstring cin cout cerr clog stdin stdout stderr stringstream istringstream ostringstream " + "auto_ptr deque list queue stack vector map set pair bitset multiset multimap unordered_set " + "unordered_map unordered_multiset unordered_multimap priority_queue make_pair array shared_ptr abort terminate abs acos " + "asin atan2 atan calloc ceil cosh cos exit exp fabs floor fmod fprintf fputs free frexp " + "fscanf future isalnum isalpha iscntrl isdigit isgraph islower isprint ispunct isspace isupper " + "isxdigit tolower toupper labs ldexp log10 log malloc realloc memchr memcmp memcpy memset modf pow " + "printf putchar puts scanf sinh sin snprintf sprintf sqrt sscanf strcat strchr strcmp " + "strcpy strcspn strlen strncat strncmp strncpy strpbrk strrchr strspn strstr tanh tan " + "vfprintf vprintf vsprintf endl initializer_list unique_ptr _Bool complex _Complex imaginary _Imaginary",
      literal: "true false nullptr NULL"
    };
    const EXPRESSION_CONTAINS = [ PREPROCESSOR, CPP_PRIMITIVE_TYPES, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, NUMBERS, STRINGS ];
    const EXPRESSION_CONTEXT = {
      // This mode covers expression context where we can't expect a function
      // definition and shouldn't highlight anything that looks like one:
      // `return some()`, `else if()`, `(x*sum(1, 2))`
      variants: [ {
        begin: /=/,
        end: /;/
      }, {
        begin: /\(/,
        end: /\)/
      }, {
        beginKeywords: "new throw return else",
        end: /;/
      } ],
      keywords: CPP_KEYWORDS,
      contains: EXPRESSION_CONTAINS.concat([ {
        begin: /\(/,
        end: /\)/,
        keywords: CPP_KEYWORDS,
        contains: EXPRESSION_CONTAINS.concat([ "self" ]),
        relevance: 0
      } ]),
      relevance: 0
    };
    const FUNCTION_DECLARATION = {
      className: "function",
      begin: "(" + FUNCTION_TYPE_RE + "[\\*&\\s]+)+" + FUNCTION_TITLE,
      returnBegin: true,
      end: /[{;=]/,
      excludeEnd: true,
      keywords: CPP_KEYWORDS,
      illegal: /[^\w\s\*&:<>]/,
      contains: [ {
        // to prevent it from being confused as the function title
        begin: DECLTYPE_AUTO_RE,
        keywords: CPP_KEYWORDS,
        relevance: 0
      }, {
        begin: FUNCTION_TITLE,
        returnBegin: true,
        contains: [ TITLE_MODE ],
        relevance: 0
      }, {
        className: "params",
        begin: /\(/,
        end: /\)/,
        keywords: CPP_KEYWORDS,
        relevance: 0,
        contains: [ C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, STRINGS, NUMBERS, CPP_PRIMITIVE_TYPES, 
        // Count matching parentheses.
        {
          begin: /\(/,
          end: /\)/,
          keywords: CPP_KEYWORDS,
          relevance: 0,
          contains: [ "self", C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, STRINGS, NUMBERS, CPP_PRIMITIVE_TYPES ]
        } ]
      }, CPP_PRIMITIVE_TYPES, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, PREPROCESSOR ]
    };
    return {
      aliases: [ "c", "cc", "h", "c++", "h++", "hpp", "hh", "hxx", "cxx" ],
      keywords: CPP_KEYWORDS,
      // the base c-like language will NEVER be auto-detected, rather the
      // derivitives: c, c++, arduino turn auto-detect back on for themselves
      disableAutodetect: true,
      illegal: "</",
      contains: [].concat(EXPRESSION_CONTEXT, FUNCTION_DECLARATION, EXPRESSION_CONTAINS, [ PREPROCESSOR, {
        // containers: ie, `vector <int> rooms (9);`
        begin: "\\b(deque|list|queue|priority_queue|pair|stack|vector|map|set|bitset|multiset|multimap|unordered_map|unordered_set|unordered_multiset|unordered_multimap|array)\\s*<",
        end: ">",
        keywords: CPP_KEYWORDS,
        contains: [ "self", CPP_PRIMITIVE_TYPES ]
      }, {
        begin: hljs.IDENT_RE + "::",
        keywords: CPP_KEYWORDS
      }, {
        className: "class",
        beginKeywords: "enum class struct union",
        end: /[{;:<>=]/,
        contains: [ {
          beginKeywords: "final class struct"
        }, hljs.TITLE_MODE ]
      } ]),
      exports: {
        preprocessor: PREPROCESSOR,
        strings: STRINGS,
        keywords: CPP_KEYWORDS
      }
    };
  }
  /*
  Language: C++
  Category: common, system
  Website: https://isocpp.org
  */
  /** @type LanguageFn */  function cpp(hljs) {
    const lang = cLike$2(hljs);
    // return auto-detection back on
        lang.disableAutodetect = false;
    lang.name = "C++";
    lang.aliases = [ "cc", "c++", "h++", "hpp", "hh", "hxx", "cxx" ];
    return lang;
  }
  var cpp_1 = cpp;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$6(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function optional$4(re) {
    return concat$6("(", re, ")?");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$6(...args) {
    const joined = args.map((x => source$6(x))).join("");
    return joined;
  }
  /*
  Language: C-like foundation grammar for C/C++ grammars
  Author: Ivan Sagalaev <maniac@softwaremaniacs.org>
  Contributors: Evgeny Stepanischev <imbolk@gmail.com>, Zaven Muradyan <megalivoithos@gmail.com>, Roel Deckers <admin@codingcat.nl>, Sam Wu <samsam2310@gmail.com>, Jordi Petit <jordi.petit@gmail.com>, Pieter Vantorre <pietervantorre@gmail.com>, Google Inc. (David Benjamin) <davidben@google.com>
  */
  /** @type LanguageFn */  function cLike$3(hljs) {
    // added for historic reasons because `hljs.C_LINE_COMMENT_MODE` does
    // not include such support nor can we be sure all the grammars depending
    // on it would desire this behavior
    const C_LINE_COMMENT_MODE = hljs.COMMENT("//", "$", {
      contains: [ {
        begin: /\\\n/
      } ]
    });
    const DECLTYPE_AUTO_RE = "decltype\\(auto\\)";
    const NAMESPACE_RE = "[a-zA-Z_]\\w*::";
    const TEMPLATE_ARGUMENT_RE = "<[^<>]+>";
    const FUNCTION_TYPE_RE = "(" + DECLTYPE_AUTO_RE + "|" + optional$4(NAMESPACE_RE) + "[a-zA-Z_]\\w*" + optional$4(TEMPLATE_ARGUMENT_RE) + ")";
    const CPP_PRIMITIVE_TYPES = {
      className: "keyword",
      begin: "\\b[a-z\\d_]*_t\\b"
    };
    // https://en.cppreference.com/w/cpp/language/escape
    // \\ \x \xFF \u2837 \u00323747 \374
        const CHARACTER_ESCAPES = "\\\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4,8}|[0-7]{3}|\\S)";
    const STRINGS = {
      className: "string",
      variants: [ {
        begin: '(u8?|U|L)?"',
        end: '"',
        illegal: "\\n",
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: "(u8?|U|L)?'(" + CHARACTER_ESCAPES + "|.)",
        end: "'",
        illegal: "."
      }, hljs.END_SAME_AS_BEGIN({
        begin: /(?:u8?|U|L)?R"([^()\\ ]{0,16})\(/,
        end: /\)([^()\\ ]{0,16})"/
      }) ]
    };
    const NUMBERS = {
      className: "number",
      variants: [ {
        begin: "\\b(0b[01']+)"
      }, {
        begin: "(-?)\\b([\\d']+(\\.[\\d']*)?|\\.[\\d']+)(u|U|l|L|ul|UL|f|F|b|B)"
      }, {
        begin: "(-?)(\\b0[xX][a-fA-F0-9']+|(\\b[\\d']+(\\.[\\d']*)?|\\.[\\d']+)([eE][-+]?[\\d']+)?)"
      } ],
      relevance: 0
    };
    const PREPROCESSOR = {
      className: "meta",
      begin: /#\s*[a-z]+\b/,
      end: /$/,
      keywords: {
        "meta-keyword": "if else elif endif define undef warning error line " + "pragma _Pragma ifdef ifndef include"
      },
      contains: [ {
        begin: /\\\n/,
        relevance: 0
      }, hljs.inherit(STRINGS, {
        className: "meta-string"
      }), {
        className: "meta-string",
        begin: /<.*?>/,
        end: /$/,
        illegal: "\\n"
      }, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE ]
    };
    const TITLE_MODE = {
      className: "title",
      begin: optional$4(NAMESPACE_RE) + hljs.IDENT_RE,
      relevance: 0
    };
    const FUNCTION_TITLE = optional$4(NAMESPACE_RE) + hljs.IDENT_RE + "\\s*\\(";
    const CPP_KEYWORDS = {
      keyword: "int float while private char char8_t char16_t char32_t catch import module export virtual operator sizeof " + "dynamic_cast|10 typedef const_cast|10 const for static_cast|10 union namespace " + "unsigned long volatile static protected bool template mutable if public friend " + "do goto auto void enum else break extern using asm case typeid wchar_t " + "short reinterpret_cast|10 default double register explicit signed typename try this " + "switch continue inline delete alignas alignof constexpr consteval constinit decltype " + "concept co_await co_return co_yield requires " + "noexcept static_assert thread_local restrict final override " + "atomic_bool atomic_char atomic_schar " + "atomic_uchar atomic_short atomic_ushort atomic_int atomic_uint atomic_long atomic_ulong atomic_llong " + "atomic_ullong new throw return " + "and and_eq bitand bitor compl not not_eq or or_eq xor xor_eq",
      built_in: "std string wstring cin cout cerr clog stdin stdout stderr stringstream istringstream ostringstream " + "auto_ptr deque list queue stack vector map set pair bitset multiset multimap unordered_set " + "unordered_map unordered_multiset unordered_multimap priority_queue make_pair array shared_ptr abort terminate abs acos " + "asin atan2 atan calloc ceil cosh cos exit exp fabs floor fmod fprintf fputs free frexp " + "fscanf future isalnum isalpha iscntrl isdigit isgraph islower isprint ispunct isspace isupper " + "isxdigit tolower toupper labs ldexp log10 log malloc realloc memchr memcmp memcpy memset modf pow " + "printf putchar puts scanf sinh sin snprintf sprintf sqrt sscanf strcat strchr strcmp " + "strcpy strcspn strlen strncat strncmp strncpy strpbrk strrchr strspn strstr tanh tan " + "vfprintf vprintf vsprintf endl initializer_list unique_ptr _Bool complex _Complex imaginary _Imaginary",
      literal: "true false nullptr NULL"
    };
    const EXPRESSION_CONTAINS = [ PREPROCESSOR, CPP_PRIMITIVE_TYPES, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, NUMBERS, STRINGS ];
    const EXPRESSION_CONTEXT = {
      // This mode covers expression context where we can't expect a function
      // definition and shouldn't highlight anything that looks like one:
      // `return some()`, `else if()`, `(x*sum(1, 2))`
      variants: [ {
        begin: /=/,
        end: /;/
      }, {
        begin: /\(/,
        end: /\)/
      }, {
        beginKeywords: "new throw return else",
        end: /;/
      } ],
      keywords: CPP_KEYWORDS,
      contains: EXPRESSION_CONTAINS.concat([ {
        begin: /\(/,
        end: /\)/,
        keywords: CPP_KEYWORDS,
        contains: EXPRESSION_CONTAINS.concat([ "self" ]),
        relevance: 0
      } ]),
      relevance: 0
    };
    const FUNCTION_DECLARATION = {
      className: "function",
      begin: "(" + FUNCTION_TYPE_RE + "[\\*&\\s]+)+" + FUNCTION_TITLE,
      returnBegin: true,
      end: /[{;=]/,
      excludeEnd: true,
      keywords: CPP_KEYWORDS,
      illegal: /[^\w\s\*&:<>]/,
      contains: [ {
        // to prevent it from being confused as the function title
        begin: DECLTYPE_AUTO_RE,
        keywords: CPP_KEYWORDS,
        relevance: 0
      }, {
        begin: FUNCTION_TITLE,
        returnBegin: true,
        contains: [ TITLE_MODE ],
        relevance: 0
      }, {
        className: "params",
        begin: /\(/,
        end: /\)/,
        keywords: CPP_KEYWORDS,
        relevance: 0,
        contains: [ C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, STRINGS, NUMBERS, CPP_PRIMITIVE_TYPES, 
        // Count matching parentheses.
        {
          begin: /\(/,
          end: /\)/,
          keywords: CPP_KEYWORDS,
          relevance: 0,
          contains: [ "self", C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, STRINGS, NUMBERS, CPP_PRIMITIVE_TYPES ]
        } ]
      }, CPP_PRIMITIVE_TYPES, C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, PREPROCESSOR ]
    };
    return {
      aliases: [ "c", "cc", "h", "c++", "h++", "hpp", "hh", "hxx", "cxx" ],
      keywords: CPP_KEYWORDS,
      // the base c-like language will NEVER be auto-detected, rather the
      // derivitives: c, c++, arduino turn auto-detect back on for themselves
      disableAutodetect: true,
      illegal: "</",
      contains: [].concat(EXPRESSION_CONTEXT, FUNCTION_DECLARATION, EXPRESSION_CONTAINS, [ PREPROCESSOR, {
        // containers: ie, `vector <int> rooms (9);`
        begin: "\\b(deque|list|queue|priority_queue|pair|stack|vector|map|set|bitset|multiset|multimap|unordered_map|unordered_set|unordered_multiset|unordered_multimap|array)\\s*<",
        end: ">",
        keywords: CPP_KEYWORDS,
        contains: [ "self", CPP_PRIMITIVE_TYPES ]
      }, {
        begin: hljs.IDENT_RE + "::",
        keywords: CPP_KEYWORDS
      }, {
        className: "class",
        beginKeywords: "enum class struct union",
        end: /[{;:<>=]/,
        contains: [ {
          beginKeywords: "final class struct"
        }, hljs.TITLE_MODE ]
      } ]),
      exports: {
        preprocessor: PREPROCESSOR,
        strings: STRINGS,
        keywords: CPP_KEYWORDS
      }
    };
  }
  /*
  Language: C++
  Category: common, system
  Website: https://isocpp.org
  */
  /** @type LanguageFn */  function cPlusPlus(hljs) {
    const lang = cLike$3(hljs);
    // return auto-detection back on
        lang.disableAutodetect = false;
    lang.name = "C++";
    lang.aliases = [ "cc", "c++", "h++", "hpp", "hh", "hxx", "cxx" ];
    return lang;
  }
  /*
  Language: Arduino
  Author: Stefania Mellai <s.mellai@arduino.cc>
  Description: The Arduino® Language is a superset of C++. This rules are designed to highlight the Arduino® source code. For info about language see http://www.arduino.cc.
  Website: https://www.arduino.cc
  */
  /** @type LanguageFn */  function arduino(hljs) {
    const ARDUINO_KW = {
      keyword: "boolean byte word String",
      built_in: "setup loop " + "KeyboardController MouseController SoftwareSerial " + "EthernetServer EthernetClient LiquidCrystal " + "RobotControl GSMVoiceCall EthernetUDP EsploraTFT " + "HttpClient RobotMotor WiFiClient GSMScanner " + "FileSystem Scheduler GSMServer YunClient YunServer " + "IPAddress GSMClient GSMModem Keyboard Ethernet " + "Console GSMBand Esplora Stepper Process " + "WiFiUDP GSM_SMS Mailbox USBHost Firmata PImage " + "Client Server GSMPIN FileIO Bridge Serial " + "EEPROM Stream Mouse Audio Servo File Task " + "GPRS WiFi Wire TFT GSM SPI SD " + "runShellCommandAsynchronously analogWriteResolution " + "retrieveCallingNumber printFirmwareVersion " + "analogReadResolution sendDigitalPortPair " + "noListenOnLocalhost readJoystickButton setFirmwareVersion " + "readJoystickSwitch scrollDisplayRight getVoiceCallStatus " + "scrollDisplayLeft writeMicroseconds delayMicroseconds " + "beginTransmission getSignalStrength runAsynchronously " + "getAsynchronously listenOnLocalhost getCurrentCarrier " + "readAccelerometer messageAvailable sendDigitalPorts " + "lineFollowConfig countryNameWrite runShellCommand " + "readStringUntil rewindDirectory readTemperature " + "setClockDivider readLightSensor endTransmission " + "analogReference detachInterrupt countryNameRead " + "attachInterrupt encryptionType readBytesUntil " + "robotNameWrite readMicrophone robotNameRead cityNameWrite " + "userNameWrite readJoystickY readJoystickX mouseReleased " + "openNextFile scanNetworks noInterrupts digitalWrite " + "beginSpeaker mousePressed isActionDone mouseDragged " + "displayLogos noAutoscroll addParameter remoteNumber " + "getModifiers keyboardRead userNameRead waitContinue " + "processInput parseCommand printVersion readNetworks " + "writeMessage blinkVersion cityNameRead readMessage " + "setDataMode parsePacket isListening setBitOrder " + "beginPacket isDirectory motorsWrite drawCompass " + "digitalRead clearScreen serialEvent rightToLeft " + "setTextSize leftToRight requestFrom keyReleased " + "compassRead analogWrite interrupts WiFiServer " + "disconnect playMelody parseFloat autoscroll " + "getPINUsed setPINUsed setTimeout sendAnalog " + "readSlider analogRead beginWrite createChar " + "motorsStop keyPressed tempoWrite readButton " + "subnetMask debugPrint macAddress writeGreen " + "randomSeed attachGPRS readString sendString " + "remotePort releaseAll mouseMoved background " + "getXChange getYChange answerCall getResult " + "voiceCall endPacket constrain getSocket writeJSON " + "getButton available connected findUntil readBytes " + "exitValue readGreen writeBlue startLoop IPAddress " + "isPressed sendSysex pauseMode gatewayIP setCursor " + "getOemKey tuneWrite noDisplay loadImage switchPIN " + "onRequest onReceive changePIN playFile noBuffer " + "parseInt overflow checkPIN knobRead beginTFT " + "bitClear updateIR bitWrite position writeRGB " + "highByte writeRed setSpeed readBlue noStroke " + "remoteIP transfer shutdown hangCall beginSMS " + "endWrite attached maintain noCursor checkReg " + "checkPUK shiftOut isValid shiftIn pulseIn " + "connect println localIP pinMode getIMEI " + "display noBlink process getBand running beginSD " + "drawBMP lowByte setBand release bitRead prepare " + "pointTo readRed setMode noFill remove listen " + "stroke detach attach noTone exists buffer " + "height bitSet circle config cursor random " + "IRread setDNS endSMS getKey micros " + "millis begin print write ready flush width " + "isPIN blink clear press mkdir rmdir close " + "point yield image BSSID click delay " + "read text move peek beep rect line open " + "seek fill size turn stop home find " + "step tone sqrt RSSI SSID " + "end bit tan cos sin pow map abs max " + "min get run put",
      literal: "DIGITAL_MESSAGE FIRMATA_STRING ANALOG_MESSAGE " + "REPORT_DIGITAL REPORT_ANALOG INPUT_PULLUP " + "SET_PIN_MODE INTERNAL2V56 SYSTEM_RESET LED_BUILTIN " + "INTERNAL1V1 SYSEX_START INTERNAL EXTERNAL " + "DEFAULT OUTPUT INPUT HIGH LOW"
    };
    const ARDUINO = cPlusPlus(hljs);
    const kws = /** @type {Record<string,any>} */ ARDUINO.keywords;
    kws.keyword += " " + ARDUINO_KW.keyword;
    kws.literal += " " + ARDUINO_KW.literal;
    kws.built_in += " " + ARDUINO_KW.built_in;
    ARDUINO.name = "Arduino";
    ARDUINO.aliases = [ "ino" ];
    ARDUINO.supersetOf = "cpp";
    return ARDUINO;
  }
  var arduino_1 = arduino;
  /*
  Language: CSS
  Category: common, css
  Website: https://developer.mozilla.org/en-US/docs/Web/CSS
  */
  /** @type LanguageFn */  function css(hljs) {
    var FUNCTION_LIKE = {
      begin: /[\w-]+\(/,
      returnBegin: true,
      contains: [ {
        className: "built_in",
        begin: /[\w-]+/
      }, {
        begin: /\(/,
        end: /\)/,
        contains: [ hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, hljs.CSS_NUMBER_MODE ]
      } ]
    };
    var ATTRIBUTE = {
      className: "attribute",
      begin: /\S/,
      end: ":",
      excludeEnd: true,
      starts: {
        endsWithParent: true,
        excludeEnd: true,
        contains: [ FUNCTION_LIKE, hljs.CSS_NUMBER_MODE, hljs.QUOTE_STRING_MODE, hljs.APOS_STRING_MODE, hljs.C_BLOCK_COMMENT_MODE, {
          className: "number",
          begin: "#[0-9A-Fa-f]+"
        }, {
          className: "meta",
          begin: "!important"
        } ]
      }
    };
    var AT_IDENTIFIER = "@[a-z-]+";
 // @font-face
        var AT_MODIFIERS = "and or not only";
    var AT_PROPERTY_RE = /@-?\w[\w]*(-\w+)*/;
 // @-webkit-keyframes
        var IDENT_RE = "[a-zA-Z-][a-zA-Z0-9_-]*";
    var RULE = {
      begin: /([*]\s?)?(?:[A-Z_.\-\\]+|--[a-zA-Z0-9_-]+)\s*(\/\*\*\/)?:/,
      returnBegin: true,
      end: ";",
      endsWithParent: true,
      contains: [ ATTRIBUTE ]
    };
    return {
      name: "CSS",
      case_insensitive: true,
      illegal: /[=|'\$]/,
      contains: [ hljs.C_BLOCK_COMMENT_MODE, {
        className: "selector-id",
        begin: /#[A-Za-z0-9_-]+/
      }, {
        className: "selector-class",
        begin: "\\." + IDENT_RE
      }, {
        className: "selector-attr",
        begin: /\[/,
        end: /\]/,
        illegal: "$",
        contains: [ hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE ]
      }, {
        className: "selector-pseudo",
        begin: /:(:)?[a-zA-Z0-9_+()"'.-]+/
      }, 
      // matching these here allows us to treat them more like regular CSS
      // rules so everything between the {} gets regular rule highlighting,
      // which is what we want for page and font-face
      {
        begin: "@(page|font-face)",
        lexemes: AT_IDENTIFIER,
        keywords: "@page @font-face"
      }, {
        begin: "@",
        end: "[{;]",
        // at_rule eating first "{" is a good thing
        // because it doesn’t let it to be parsed as
        // a rule set but instead drops parser into
        // the default mode which is how it should be.
        illegal: /:/,
        // break on Less variables @var: ...
        returnBegin: true,
        contains: [ {
          className: "keyword",
          begin: AT_PROPERTY_RE
        }, {
          begin: /\s/,
          endsWithParent: true,
          excludeEnd: true,
          relevance: 0,
          keywords: AT_MODIFIERS,
          contains: [ {
            begin: /[a-z-]+:/,
            className: "attribute"
          }, hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, hljs.CSS_NUMBER_MODE ]
        } ]
      }, {
        className: "selector-tag",
        begin: IDENT_RE,
        relevance: 0
      }, {
        begin: /\{/,
        end: /\}/,
        illegal: /\S/,
        contains: [ hljs.C_BLOCK_COMMENT_MODE, {
          begin: /;/
        }, // empty ; rule
        RULE ]
      } ]
    };
  }
  var css_1 = css;
  /*
  Language: Diff
  Description: Unified and context diff
  Author: Vasily Polovnyov <vast@whiteants.net>
  Website: https://www.gnu.org/software/diffutils/
  Category: common
  */
  /** @type LanguageFn */  function diff(hljs) {
    return {
      name: "Diff",
      aliases: [ "patch" ],
      contains: [ {
        className: "meta",
        relevance: 10,
        variants: [ {
          begin: /^@@ +-\d+,\d+ +\+\d+,\d+ +@@/
        }, {
          begin: /^\*\*\* +\d+,\d+ +\*\*\*\*$/
        }, {
          begin: /^--- +\d+,\d+ +----$/
        } ]
      }, {
        className: "comment",
        variants: [ {
          begin: /Index: /,
          end: /$/
        }, {
          begin: /^index/,
          end: /$/
        }, {
          begin: /={3,}/,
          end: /$/
        }, {
          begin: /^-{3}/,
          end: /$/
        }, {
          begin: /^\*{3} /,
          end: /$/
        }, {
          begin: /^\+{3}/,
          end: /$/
        }, {
          begin: /^\*{15}$/
        }, {
          begin: /^diff --git/,
          end: /$/
        } ]
      }, {
        className: "addition",
        begin: /^\+/,
        end: /$/
      }, {
        className: "deletion",
        begin: /^-/,
        end: /$/
      }, {
        className: "addition",
        begin: /^!/,
        end: /$/
      } ]
    };
  }
  var diff_1 = diff;
  /*
  Language: Django
  Description: Django is a high-level Python Web framework that encourages rapid development and clean, pragmatic design.
  Requires: xml.js
  Author: Ivan Sagalaev <maniac@softwaremaniacs.org>
  Contributors: Ilya Baryshev <baryshev@gmail.com>
  Website: https://www.djangoproject.com
  Category: template
  */
  /** @type LanguageFn */  function django(hljs) {
    const FILTER = {
      begin: /\|[A-Za-z]+:?/,
      keywords: {
        name: "truncatewords removetags linebreaksbr yesno get_digit timesince random striptags " + "filesizeformat escape linebreaks length_is ljust rjust cut urlize fix_ampersands " + "title floatformat capfirst pprint divisibleby add make_list unordered_list urlencode " + "timeuntil urlizetrunc wordcount stringformat linenumbers slice date dictsort " + "dictsortreversed default_if_none pluralize lower join center default " + "truncatewords_html upper length phone2numeric wordwrap time addslashes slugify first " + "escapejs force_escape iriencode last safe safeseq truncatechars localize unlocalize " + "localtime utc timezone"
      },
      contains: [ hljs.QUOTE_STRING_MODE, hljs.APOS_STRING_MODE ]
    };
    return {
      name: "Django",
      aliases: [ "jinja" ],
      case_insensitive: true,
      subLanguage: "xml",
      contains: [ hljs.COMMENT(/\{%\s*comment\s*%\}/, /\{%\s*endcomment\s*%\}/), hljs.COMMENT(/\{#/, /#\}/), {
        className: "template-tag",
        begin: /\{%/,
        end: /%\}/,
        contains: [ {
          className: "name",
          begin: /\w+/,
          keywords: {
            name: "comment endcomment load templatetag ifchanged endifchanged if endif firstof for " + "endfor ifnotequal endifnotequal widthratio extends include spaceless " + "endspaceless regroup ifequal endifequal ssi now with cycle url filter " + "endfilter debug block endblock else autoescape endautoescape csrf_token empty elif " + "endwith static trans blocktrans endblocktrans get_static_prefix get_media_prefix " + "plural get_current_language language get_available_languages " + "get_current_language_bidi get_language_info get_language_info_list localize " + "endlocalize localtime endlocaltime timezone endtimezone get_current_timezone " + "verbatim"
          },
          starts: {
            endsWithParent: true,
            keywords: "in by as",
            contains: [ FILTER ],
            relevance: 0
          }
        } ]
      }, {
        className: "template-variable",
        begin: /\{\{/,
        end: /\}\}/,
        contains: [ FILTER ]
      } ]
    };
  }
  var django_1 = django;
  /*
  Language: Dockerfile
  Requires: bash.js
  Author: Alexis Hénaut <alexis@henaut.net>
  Description: language definition for Dockerfile files
  Website: https://docs.docker.com/engine/reference/builder/
  Category: config
  */
  /** @type LanguageFn */  function dockerfile(hljs) {
    return {
      name: "Dockerfile",
      aliases: [ "docker" ],
      case_insensitive: true,
      keywords: "from maintainer expose env arg user onbuild stopsignal",
      contains: [ hljs.HASH_COMMENT_MODE, hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, hljs.NUMBER_MODE, {
        beginKeywords: "run cmd entrypoint volume add copy workdir label healthcheck shell",
        starts: {
          end: /[^\\]$/,
          subLanguage: "bash"
        }
      } ],
      illegal: "</"
    };
  }
  var dockerfile_1 = dockerfile;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$7(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function lookahead$1(re) {
    return concat$7("(?=", re, ")");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$7(...args) {
    const joined = args.map((x => source$7(x))).join("");
    return joined;
  }
  /*
  Language: Ruby
  Description: Ruby is a dynamic, open source programming language with a focus on simplicity and productivity.
  Website: https://www.ruby-lang.org/
  Author: Anton Kovalyov <anton@kovalyov.net>
  Contributors: Peter Leonov <gojpeg@yandex.ru>, Vasily Polovnyov <vast@whiteants.net>, Loren Segal <lsegal@soen.ca>, Pascal Hurni <phi@ruby-reactive.org>, Cedric Sohrauer <sohrauer@googlemail.com>
  Category: common
  */  function ruby(hljs) {
    var RUBY_METHOD_RE = "([a-zA-Z_]\\w*[!?=]?|[-+~]@|<<|>>|=~|===?|<=>|[<>]=?|\\*\\*|[-/+%^&*~`|]|\\[\\]=?)";
    var RUBY_KEYWORDS = {
      keyword: "and then defined module in return redo if BEGIN retry end for self when " + "next until do begin unless END rescue else break undef not super class case " + "require yield alias while ensure elsif or include attr_reader attr_writer attr_accessor " + "__FILE__",
      built_in: "proc lambda",
      literal: "true false nil"
    };
    var YARDOCTAG = {
      className: "doctag",
      begin: "@[A-Za-z]+"
    };
    var IRB_OBJECT = {
      begin: "#<",
      end: ">"
    };
    var COMMENT_MODES = [ hljs.COMMENT("#", "$", {
      contains: [ YARDOCTAG ]
    }), hljs.COMMENT("^=begin", "^=end", {
      contains: [ YARDOCTAG ],
      relevance: 10
    }), hljs.COMMENT("^__END__", "\\n$") ];
    var SUBST = {
      className: "subst",
      begin: /#\{/,
      end: /\}/,
      keywords: RUBY_KEYWORDS
    };
    var STRING = {
      className: "string",
      contains: [ hljs.BACKSLASH_ESCAPE, SUBST ],
      variants: [ {
        begin: /'/,
        end: /'/
      }, {
        begin: /"/,
        end: /"/
      }, {
        begin: /`/,
        end: /`/
      }, {
        begin: /%[qQwWx]?\(/,
        end: /\)/
      }, {
        begin: /%[qQwWx]?\[/,
        end: /\]/
      }, {
        begin: /%[qQwWx]?\{/,
        end: /\}/
      }, {
        begin: /%[qQwWx]?</,
        end: />/
      }, {
        begin: /%[qQwWx]?\//,
        end: /\//
      }, {
        begin: /%[qQwWx]?%/,
        end: /%/
      }, {
        begin: /%[qQwWx]?-/,
        end: /-/
      }, {
        begin: /%[qQwWx]?\|/,
        end: /\|/
      }, {
        // \B in the beginning suppresses recognition of ?-sequences where ?
        // is the last character of a preceding identifier, as in: `func?4`
        begin: /\B\?(\\\d{1,3}|\\x[A-Fa-f0-9]{1,2}|\\u[A-Fa-f0-9]{4}|\\?\S)\b/
      }, {
        // heredocs
        begin: /<<[-~]?'?(\w+)\n(?:[^\n]*\n)*?\s*\1\b/,
        returnBegin: true,
        contains: [ {
          begin: /<<[-~]?'?/
        }, hljs.END_SAME_AS_BEGIN({
          begin: /(\w+)/,
          end: /(\w+)/,
          contains: [ hljs.BACKSLASH_ESCAPE, SUBST ]
        }) ]
      } ]
    };
    // Ruby syntax is underdocumented, but this grammar seems to be accurate
    // as of version 2.7.2 (confirmed with (irb and `Ripper.sexp(...)`)
    // https://docs.ruby-lang.org/en/2.7.0/doc/syntax/literals_rdoc.html#label-Numbers
        var decimal = "[1-9](_?[0-9])*|0";
    var digits = "[0-9](_?[0-9])*";
    var NUMBER = {
      className: "number",
      relevance: 0,
      variants: [ 
      // decimal integer/float, optionally exponential or rational, optionally imaginary
      {
        begin: `\\b(${decimal})(\\.(${digits}))?([eE][+-]?(${digits})|r)?i?\\b`
      }, 
      // explicit decimal/binary/octal/hexadecimal integer,
      // optionally rational and/or imaginary
      {
        begin: "\\b0[dD][0-9](_?[0-9])*r?i?\\b"
      }, {
        begin: "\\b0[bB][0-1](_?[0-1])*r?i?\\b"
      }, {
        begin: "\\b0[oO][0-7](_?[0-7])*r?i?\\b"
      }, {
        begin: "\\b0[xX][0-9a-fA-F](_?[0-9a-fA-F])*r?i?\\b"
      }, 
      // 0-prefixed implicit octal integer, optionally rational and/or imaginary
      {
        begin: "\\b0(_?[0-7])+r?i?\\b"
      } ]
    };
    var PARAMS = {
      className: "params",
      begin: "\\(",
      end: "\\)",
      endsParent: true,
      keywords: RUBY_KEYWORDS
    };
    var RUBY_DEFAULT_CONTAINS = [ STRING, {
      className: "class",
      beginKeywords: "class module",
      end: "$|;",
      illegal: /=/,
      contains: [ hljs.inherit(hljs.TITLE_MODE, {
        begin: "[A-Za-z_]\\w*(::\\w+)*(\\?|!)?"
      }), {
        begin: "<\\s*",
        contains: [ {
          begin: "(" + hljs.IDENT_RE + "::)?" + hljs.IDENT_RE
        } ]
      } ].concat(COMMENT_MODES)
    }, {
      className: "function",
      // def method_name(
      // def method_name;
      // def method_name (end of line)
      begin: concat$7(/def\s*/, lookahead$1(RUBY_METHOD_RE + "\\s*(\\(|;|$)")),
      keywords: "def",
      end: "$|;",
      contains: [ hljs.inherit(hljs.TITLE_MODE, {
        begin: RUBY_METHOD_RE
      }), PARAMS ].concat(COMMENT_MODES)
    }, {
      // swallow namespace qualifiers before symbols
      begin: hljs.IDENT_RE + "::"
    }, {
      className: "symbol",
      begin: hljs.UNDERSCORE_IDENT_RE + "(!|\\?)?:",
      relevance: 0
    }, {
      className: "symbol",
      begin: ":(?!\\s)",
      contains: [ STRING, {
        begin: RUBY_METHOD_RE
      } ],
      relevance: 0
    }, NUMBER, {
      // negative-look forward attemps to prevent false matches like:
      // @ident@ or $ident$ that might indicate this is not ruby at all
      className: "variable",
      begin: "(\\$\\W)|((\\$|@@?)(\\w+))(?=[^@$?])" + `(?![A-Za-z])(?![@$?'])`
    }, {
      className: "params",
      begin: /\|/,
      end: /\|/,
      relevance: 0,
      // this could be a lot of things (in other languages) other than params
      keywords: RUBY_KEYWORDS
    }, {
      // regexp container
      begin: "(" + hljs.RE_STARTERS_RE + "|unless)\\s*",
      keywords: "unless",
      contains: [ {
        className: "regexp",
        contains: [ hljs.BACKSLASH_ESCAPE, SUBST ],
        illegal: /\n/,
        variants: [ {
          begin: "/",
          end: "/[a-z]*"
        }, {
          begin: /%r\{/,
          end: /\}[a-z]*/
        }, {
          begin: "%r\\(",
          end: "\\)[a-z]*"
        }, {
          begin: "%r!",
          end: "![a-z]*"
        }, {
          begin: "%r\\[",
          end: "\\][a-z]*"
        } ]
      } ].concat(IRB_OBJECT, COMMENT_MODES),
      relevance: 0
    } ].concat(IRB_OBJECT, COMMENT_MODES);
    SUBST.contains = RUBY_DEFAULT_CONTAINS;
    PARAMS.contains = RUBY_DEFAULT_CONTAINS;
    // >>
    // ?>
        var SIMPLE_PROMPT = "[>?]>";
    // irb(main):001:0>
        var DEFAULT_PROMPT = "[\\w#]+\\(\\w+\\):\\d+:\\d+>";
    var RVM_PROMPT = "(\\w+-)?\\d+\\.\\d+\\.\\d+(p\\d+)?[^\\d][^>]+>";
    var IRB_DEFAULT = [ {
      begin: /^\s*=>/,
      starts: {
        end: "$",
        contains: RUBY_DEFAULT_CONTAINS
      }
    }, {
      className: "meta",
      begin: "^(" + SIMPLE_PROMPT + "|" + DEFAULT_PROMPT + "|" + RVM_PROMPT + ")(?=[ ])",
      starts: {
        end: "$",
        contains: RUBY_DEFAULT_CONTAINS
      }
    } ];
    COMMENT_MODES.unshift(IRB_OBJECT);
    return {
      name: "Ruby",
      aliases: [ "rb", "gemspec", "podspec", "thor", "irb" ],
      keywords: RUBY_KEYWORDS,
      illegal: /\/\*/,
      contains: [ hljs.SHEBANG({
        binary: "ruby"
      }) ].concat(IRB_DEFAULT).concat(COMMENT_MODES).concat(RUBY_DEFAULT_CONTAINS)
    };
  }
  var ruby_1 = ruby;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$8(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$8(...args) {
    const joined = args.map((x => source$8(x))).join("");
    return joined;
  }
  /*
  Language: Fortran
  Author: Anthony Scemama <scemama@irsamc.ups-tlse.fr>
  Website: https://en.wikipedia.org/wiki/Fortran
  Category: scientific
  */
  /** @type LanguageFn */  function fortran(hljs) {
    const PARAMS = {
      className: "params",
      begin: "\\(",
      end: "\\)"
    };
    const COMMENT = {
      variants: [ hljs.COMMENT("!", "$", {
        relevance: 0
      }), 
      // allow FORTRAN 77 style comments
      hljs.COMMENT("^C[ ]", "$", {
        relevance: 0
      }), hljs.COMMENT("^C$", "$", {
        relevance: 0
      }) ]
    };
    // regex in both fortran and irpf90 should match
        const OPTIONAL_NUMBER_SUFFIX = /(_[a-z_\d]+)?/;
    const OPTIONAL_NUMBER_EXP = /([de][+-]?\d+)?/;
    const NUMBER = {
      className: "number",
      variants: [ {
        begin: concat$8(/\b\d+/, /\.(\d*)/, OPTIONAL_NUMBER_EXP, OPTIONAL_NUMBER_SUFFIX)
      }, {
        begin: concat$8(/\b\d+/, OPTIONAL_NUMBER_EXP, OPTIONAL_NUMBER_SUFFIX)
      }, {
        begin: concat$8(/\.\d+/, OPTIONAL_NUMBER_EXP, OPTIONAL_NUMBER_SUFFIX)
      } ],
      relevance: 0
    };
    const FUNCTION_DEF = {
      className: "function",
      beginKeywords: "subroutine function program",
      illegal: "[${=\\n]",
      contains: [ hljs.UNDERSCORE_TITLE_MODE, PARAMS ]
    };
    const STRING = {
      className: "string",
      relevance: 0,
      variants: [ hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE ]
    };
    const KEYWORDS = {
      literal: ".False. .True.",
      keyword: "kind do concurrent local shared while private call intrinsic where elsewhere " + "type endtype endmodule endselect endinterface end enddo endif if forall endforall only contains default return stop then block endblock endassociate " + "public subroutine|10 function program .and. .or. .not. .le. .eq. .ge. .gt. .lt. " + "goto save else use module select case " + "access blank direct exist file fmt form formatted iostat name named nextrec number opened rec recl sequential status unformatted unit " + "continue format pause cycle exit " + "c_null_char c_alert c_backspace c_form_feed flush wait decimal round iomsg " + "synchronous nopass non_overridable pass protected volatile abstract extends import " + "non_intrinsic value deferred generic final enumerator class associate bind enum " + "c_int c_short c_long c_long_long c_signed_char c_size_t c_int8_t c_int16_t c_int32_t c_int64_t c_int_least8_t c_int_least16_t " + "c_int_least32_t c_int_least64_t c_int_fast8_t c_int_fast16_t c_int_fast32_t c_int_fast64_t c_intmax_t C_intptr_t c_float c_double " + "c_long_double c_float_complex c_double_complex c_long_double_complex c_bool c_char c_null_ptr c_null_funptr " + "c_new_line c_carriage_return c_horizontal_tab c_vertical_tab iso_c_binding c_loc c_funloc c_associated  c_f_pointer " + "c_ptr c_funptr iso_fortran_env character_storage_size error_unit file_storage_size input_unit iostat_end iostat_eor " + "numeric_storage_size output_unit c_f_procpointer ieee_arithmetic ieee_support_underflow_control " + "ieee_get_underflow_mode ieee_set_underflow_mode newunit contiguous recursive " + "pad position action delim readwrite eor advance nml interface procedure namelist include sequence elemental pure impure " + "integer real character complex logical codimension dimension allocatable|10 parameter " + "external implicit|10 none double precision assign intent optional pointer " + "target in out common equivalence data",
      built_in: "alog alog10 amax0 amax1 amin0 amin1 amod cabs ccos cexp clog csin csqrt dabs dacos dasin datan datan2 dcos dcosh ddim dexp dint " + "dlog dlog10 dmax1 dmin1 dmod dnint dsign dsin dsinh dsqrt dtan dtanh float iabs idim idint idnint ifix isign max0 max1 min0 min1 sngl " + "algama cdabs cdcos cdexp cdlog cdsin cdsqrt cqabs cqcos cqexp cqlog cqsin cqsqrt dcmplx dconjg derf derfc dfloat dgamma dimag dlgama " + "iqint qabs qacos qasin qatan qatan2 qcmplx qconjg qcos qcosh qdim qerf qerfc qexp qgamma qimag qlgama qlog qlog10 qmax1 qmin1 qmod " + "qnint qsign qsin qsinh qsqrt qtan qtanh abs acos aimag aint anint asin atan atan2 char cmplx conjg cos cosh exp ichar index int log " + "log10 max min nint sign sin sinh sqrt tan tanh print write dim lge lgt lle llt mod nullify allocate deallocate " + "adjustl adjustr all allocated any associated bit_size btest ceiling count cshift date_and_time digits dot_product " + "eoshift epsilon exponent floor fraction huge iand ibclr ibits ibset ieor ior ishft ishftc lbound len_trim matmul " + "maxexponent maxloc maxval merge minexponent minloc minval modulo mvbits nearest pack present product " + "radix random_number random_seed range repeat reshape rrspacing scale scan selected_int_kind selected_real_kind " + "set_exponent shape size spacing spread sum system_clock tiny transpose trim ubound unpack verify achar iachar transfer " + "dble entry dprod cpu_time command_argument_count get_command get_command_argument get_environment_variable is_iostat_end " + "ieee_arithmetic ieee_support_underflow_control ieee_get_underflow_mode ieee_set_underflow_mode " + "is_iostat_eor move_alloc new_line selected_char_kind same_type_as extends_type_of " + "acosh asinh atanh bessel_j0 bessel_j1 bessel_jn bessel_y0 bessel_y1 bessel_yn erf erfc erfc_scaled gamma log_gamma hypot norm2 " + "atomic_define atomic_ref execute_command_line leadz trailz storage_size merge_bits " + "bge bgt ble blt dshiftl dshiftr findloc iall iany iparity image_index lcobound ucobound maskl maskr " + "num_images parity popcnt poppar shifta shiftl shiftr this_image sync change team co_broadcast co_max co_min co_sum co_reduce"
    };
    return {
      name: "Fortran",
      case_insensitive: true,
      aliases: [ "f90", "f95" ],
      keywords: KEYWORDS,
      illegal: /\/\*/,
      contains: [ STRING, FUNCTION_DEF, 
      // allow `C = value` for assignments so they aren't misdetected
      // as Fortran 77 style comments
      {
        begin: /^C\s*=(?!=)/,
        relevance: 0
      }, COMMENT, NUMBER ]
    };
  }
  var fortran_1 = fortran;
  /*
  Language: GLSL
  Description: OpenGL Shading Language
  Author: Sergey Tikhomirov <sergey@tikhomirov.io>
  Website: https://en.wikipedia.org/wiki/OpenGL_Shading_Language
  Category: graphics
  */  function glsl(hljs) {
    return {
      name: "GLSL",
      keywords: {
        keyword: 
        // Statements
        "break continue discard do else for if return while switch case default " + 
        // Qualifiers
        "attribute binding buffer ccw centroid centroid varying coherent column_major const cw " + "depth_any depth_greater depth_less depth_unchanged early_fragment_tests equal_spacing " + "flat fractional_even_spacing fractional_odd_spacing highp in index inout invariant " + "invocations isolines layout line_strip lines lines_adjacency local_size_x local_size_y " + "local_size_z location lowp max_vertices mediump noperspective offset origin_upper_left " + "out packed patch pixel_center_integer point_mode points precise precision quads r11f_g11f_b10f " + "r16 r16_snorm r16f r16i r16ui r32f r32i r32ui r8 r8_snorm r8i r8ui readonly restrict " + "rg16 rg16_snorm rg16f rg16i rg16ui rg32f rg32i rg32ui rg8 rg8_snorm rg8i rg8ui rgb10_a2 " + "rgb10_a2ui rgba16 rgba16_snorm rgba16f rgba16i rgba16ui rgba32f rgba32i rgba32ui rgba8 " + "rgba8_snorm rgba8i rgba8ui row_major sample shared smooth std140 std430 stream triangle_strip " + "triangles triangles_adjacency uniform varying vertices volatile writeonly",
        type: "atomic_uint bool bvec2 bvec3 bvec4 dmat2 dmat2x2 dmat2x3 dmat2x4 dmat3 dmat3x2 dmat3x3 " + "dmat3x4 dmat4 dmat4x2 dmat4x3 dmat4x4 double dvec2 dvec3 dvec4 float iimage1D iimage1DArray " + "iimage2D iimage2DArray iimage2DMS iimage2DMSArray iimage2DRect iimage3D iimageBuffer " + "iimageCube iimageCubeArray image1D image1DArray image2D image2DArray image2DMS image2DMSArray " + "image2DRect image3D imageBuffer imageCube imageCubeArray int isampler1D isampler1DArray " + "isampler2D isampler2DArray isampler2DMS isampler2DMSArray isampler2DRect isampler3D " + "isamplerBuffer isamplerCube isamplerCubeArray ivec2 ivec3 ivec4 mat2 mat2x2 mat2x3 " + "mat2x4 mat3 mat3x2 mat3x3 mat3x4 mat4 mat4x2 mat4x3 mat4x4 sampler1D sampler1DArray " + "sampler1DArrayShadow sampler1DShadow sampler2D sampler2DArray sampler2DArrayShadow " + "sampler2DMS sampler2DMSArray sampler2DRect sampler2DRectShadow sampler2DShadow sampler3D " + "samplerBuffer samplerCube samplerCubeArray samplerCubeArrayShadow samplerCubeShadow " + "image1D uimage1DArray uimage2D uimage2DArray uimage2DMS uimage2DMSArray uimage2DRect " + "uimage3D uimageBuffer uimageCube uimageCubeArray uint usampler1D usampler1DArray " + "usampler2D usampler2DArray usampler2DMS usampler2DMSArray usampler2DRect usampler3D " + "samplerBuffer usamplerCube usamplerCubeArray uvec2 uvec3 uvec4 vec2 vec3 vec4 void",
        built_in: 
        // Constants
        "gl_MaxAtomicCounterBindings gl_MaxAtomicCounterBufferSize gl_MaxClipDistances gl_MaxClipPlanes " + "gl_MaxCombinedAtomicCounterBuffers gl_MaxCombinedAtomicCounters gl_MaxCombinedImageUniforms " + "gl_MaxCombinedImageUnitsAndFragmentOutputs gl_MaxCombinedTextureImageUnits gl_MaxComputeAtomicCounterBuffers " + "gl_MaxComputeAtomicCounters gl_MaxComputeImageUniforms gl_MaxComputeTextureImageUnits " + "gl_MaxComputeUniformComponents gl_MaxComputeWorkGroupCount gl_MaxComputeWorkGroupSize " + "gl_MaxDrawBuffers gl_MaxFragmentAtomicCounterBuffers gl_MaxFragmentAtomicCounters " + "gl_MaxFragmentImageUniforms gl_MaxFragmentInputComponents gl_MaxFragmentInputVectors " + "gl_MaxFragmentUniformComponents gl_MaxFragmentUniformVectors gl_MaxGeometryAtomicCounterBuffers " + "gl_MaxGeometryAtomicCounters gl_MaxGeometryImageUniforms gl_MaxGeometryInputComponents " + "gl_MaxGeometryOutputComponents gl_MaxGeometryOutputVertices gl_MaxGeometryTextureImageUnits " + "gl_MaxGeometryTotalOutputComponents gl_MaxGeometryUniformComponents gl_MaxGeometryVaryingComponents " + "gl_MaxImageSamples gl_MaxImageUnits gl_MaxLights gl_MaxPatchVertices gl_MaxProgramTexelOffset " + "gl_MaxTessControlAtomicCounterBuffers gl_MaxTessControlAtomicCounters gl_MaxTessControlImageUniforms " + "gl_MaxTessControlInputComponents gl_MaxTessControlOutputComponents gl_MaxTessControlTextureImageUnits " + "gl_MaxTessControlTotalOutputComponents gl_MaxTessControlUniformComponents " + "gl_MaxTessEvaluationAtomicCounterBuffers gl_MaxTessEvaluationAtomicCounters " + "gl_MaxTessEvaluationImageUniforms gl_MaxTessEvaluationInputComponents gl_MaxTessEvaluationOutputComponents " + "gl_MaxTessEvaluationTextureImageUnits gl_MaxTessEvaluationUniformComponents " + "gl_MaxTessGenLevel gl_MaxTessPatchComponents gl_MaxTextureCoords gl_MaxTextureImageUnits " + "gl_MaxTextureUnits gl_MaxVaryingComponents gl_MaxVaryingFloats gl_MaxVaryingVectors " + "gl_MaxVertexAtomicCounterBuffers gl_MaxVertexAtomicCounters gl_MaxVertexAttribs gl_MaxVertexImageUniforms " + "gl_MaxVertexOutputComponents gl_MaxVertexOutputVectors gl_MaxVertexTextureImageUnits " + "gl_MaxVertexUniformComponents gl_MaxVertexUniformVectors gl_MaxViewports gl_MinProgramTexelOffset " + 
        // Variables
        "gl_BackColor gl_BackLightModelProduct gl_BackLightProduct gl_BackMaterial " + "gl_BackSecondaryColor gl_ClipDistance gl_ClipPlane gl_ClipVertex gl_Color " + "gl_DepthRange gl_EyePlaneQ gl_EyePlaneR gl_EyePlaneS gl_EyePlaneT gl_Fog gl_FogCoord " + "gl_FogFragCoord gl_FragColor gl_FragCoord gl_FragData gl_FragDepth gl_FrontColor " + "gl_FrontFacing gl_FrontLightModelProduct gl_FrontLightProduct gl_FrontMaterial " + "gl_FrontSecondaryColor gl_GlobalInvocationID gl_InstanceID gl_InvocationID gl_Layer gl_LightModel " + "gl_LightSource gl_LocalInvocationID gl_LocalInvocationIndex gl_ModelViewMatrix " + "gl_ModelViewMatrixInverse gl_ModelViewMatrixInverseTranspose gl_ModelViewMatrixTranspose " + "gl_ModelViewProjectionMatrix gl_ModelViewProjectionMatrixInverse gl_ModelViewProjectionMatrixInverseTranspose " + "gl_ModelViewProjectionMatrixTranspose gl_MultiTexCoord0 gl_MultiTexCoord1 gl_MultiTexCoord2 " + "gl_MultiTexCoord3 gl_MultiTexCoord4 gl_MultiTexCoord5 gl_MultiTexCoord6 gl_MultiTexCoord7 " + "gl_Normal gl_NormalMatrix gl_NormalScale gl_NumSamples gl_NumWorkGroups gl_ObjectPlaneQ " + "gl_ObjectPlaneR gl_ObjectPlaneS gl_ObjectPlaneT gl_PatchVerticesIn gl_Point gl_PointCoord " + "gl_PointSize gl_Position gl_PrimitiveID gl_PrimitiveIDIn gl_ProjectionMatrix gl_ProjectionMatrixInverse " + "gl_ProjectionMatrixInverseTranspose gl_ProjectionMatrixTranspose gl_SampleID gl_SampleMask " + "gl_SampleMaskIn gl_SamplePosition gl_SecondaryColor gl_TessCoord gl_TessLevelInner gl_TessLevelOuter " + "gl_TexCoord gl_TextureEnvColor gl_TextureMatrix gl_TextureMatrixInverse gl_TextureMatrixInverseTranspose " + "gl_TextureMatrixTranspose gl_Vertex gl_VertexID gl_ViewportIndex gl_WorkGroupID gl_WorkGroupSize gl_in gl_out " + 
        // Functions
        "EmitStreamVertex EmitVertex EndPrimitive EndStreamPrimitive abs acos acosh all any asin " + "asinh atan atanh atomicAdd atomicAnd atomicCompSwap atomicCounter atomicCounterDecrement " + "atomicCounterIncrement atomicExchange atomicMax atomicMin atomicOr atomicXor barrier " + "bitCount bitfieldExtract bitfieldInsert bitfieldReverse ceil clamp cos cosh cross " + "dFdx dFdy degrees determinant distance dot equal exp exp2 faceforward findLSB findMSB " + "floatBitsToInt floatBitsToUint floor fma fract frexp ftransform fwidth greaterThan " + "greaterThanEqual groupMemoryBarrier imageAtomicAdd imageAtomicAnd imageAtomicCompSwap " + "imageAtomicExchange imageAtomicMax imageAtomicMin imageAtomicOr imageAtomicXor imageLoad " + "imageSize imageStore imulExtended intBitsToFloat interpolateAtCentroid interpolateAtOffset " + "interpolateAtSample inverse inversesqrt isinf isnan ldexp length lessThan lessThanEqual log " + "log2 matrixCompMult max memoryBarrier memoryBarrierAtomicCounter memoryBarrierBuffer " + "memoryBarrierImage memoryBarrierShared min mix mod modf noise1 noise2 noise3 noise4 " + "normalize not notEqual outerProduct packDouble2x32 packHalf2x16 packSnorm2x16 packSnorm4x8 " + "packUnorm2x16 packUnorm4x8 pow radians reflect refract round roundEven shadow1D shadow1DLod " + "shadow1DProj shadow1DProjLod shadow2D shadow2DLod shadow2DProj shadow2DProjLod sign sin sinh " + "smoothstep sqrt step tan tanh texelFetch texelFetchOffset texture texture1D texture1DLod " + "texture1DProj texture1DProjLod texture2D texture2DLod texture2DProj texture2DProjLod " + "texture3D texture3DLod texture3DProj texture3DProjLod textureCube textureCubeLod " + "textureGather textureGatherOffset textureGatherOffsets textureGrad textureGradOffset " + "textureLod textureLodOffset textureOffset textureProj textureProjGrad textureProjGradOffset " + "textureProjLod textureProjLodOffset textureProjOffset textureQueryLevels textureQueryLod " + "textureSize transpose trunc uaddCarry uintBitsToFloat umulExtended unpackDouble2x32 " + "unpackHalf2x16 unpackSnorm2x16 unpackSnorm4x8 unpackUnorm2x16 unpackUnorm4x8 usubBorrow",
        literal: "true false"
      },
      illegal: '"',
      contains: [ hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, hljs.C_NUMBER_MODE, {
        className: "meta",
        begin: "#",
        end: "$"
      } ]
    };
  }
  var glsl_1 = glsl;
  /*
  Language: Go
  Author: Stephan Kountso aka StepLg <steplg@gmail.com>
  Contributors: Evgeny Stepanischev <imbolk@gmail.com>
  Description: Google go language (golang). For info about language
  Website: http://golang.org/
  Category: common, system
  */  function go(hljs) {
    const GO_KEYWORDS = {
      keyword: "break default func interface select case map struct chan else goto package switch " + "const fallthrough if range type continue for import return var go defer " + "bool byte complex64 complex128 float32 float64 int8 int16 int32 int64 string uint8 " + "uint16 uint32 uint64 int uint uintptr rune",
      literal: "true false iota nil",
      built_in: "append cap close complex copy imag len make new panic print println real recover delete"
    };
    return {
      name: "Go",
      aliases: [ "golang" ],
      keywords: GO_KEYWORDS,
      illegal: "</",
      contains: [ hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, {
        className: "string",
        variants: [ hljs.QUOTE_STRING_MODE, hljs.APOS_STRING_MODE, {
          begin: "`",
          end: "`"
        } ]
      }, {
        className: "number",
        variants: [ {
          begin: hljs.C_NUMBER_RE + "[i]",
          relevance: 1
        }, hljs.C_NUMBER_MODE ]
      }, {
        begin: /:=/
      }, {
        className: "function",
        beginKeywords: "func",
        end: "\\s*(\\{|$)",
        excludeEnd: true,
        contains: [ hljs.TITLE_MODE, {
          className: "params",
          begin: /\(/,
          end: /\)/,
          keywords: GO_KEYWORDS,
          illegal: /["']/
        } ]
      } ]
    };
  }
  var go_1 = go;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$9(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function lookahead$2(re) {
    return concat$9("(?=", re, ")");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$9(...args) {
    const joined = args.map((x => source$9(x))).join("");
    return joined;
  }
  /*
   Language: Groovy
   Author: Guillaume Laforge <glaforge@gmail.com>
   Description: Groovy programming language implementation inspired from Vsevolod's Java mode
   Website: https://groovy-lang.org
   */  function variants(variants, obj = {}) {
    obj.variants = variants;
    return obj;
  }
  function groovy(hljs) {
    const IDENT_RE = "[A-Za-z0-9_$]+";
    const COMMENT = variants([ hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, hljs.COMMENT("/\\*\\*", "\\*/", {
      relevance: 0,
      contains: [ {
        // eat up @'s in emails to prevent them to be recognized as doctags
        begin: /\w+@/,
        relevance: 0
      }, {
        className: "doctag",
        begin: "@[A-Za-z]+"
      } ]
    }) ]);
    const REGEXP = {
      className: "regexp",
      begin: /~?\/[^\/\n]+\//,
      contains: [ hljs.BACKSLASH_ESCAPE ]
    };
    const NUMBER = variants([ hljs.BINARY_NUMBER_MODE, hljs.C_NUMBER_MODE ]);
    const STRING = variants([ {
      begin: /"""/,
      end: /"""/
    }, {
      begin: /'''/,
      end: /'''/
    }, {
      begin: "\\$/",
      end: "/\\$",
      relevance: 10
    }, hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE ], {
      className: "string"
    });
    return {
      name: "Groovy",
      keywords: {
        built_in: "this super",
        literal: "true false null",
        keyword: "byte short char int long boolean float double void " + 
        // groovy specific keywords
        "def as in assert trait " + 
        // common keywords with Java
        "abstract static volatile transient public private protected synchronized final " + "class interface enum if else for while switch case break default continue " + "throw throws try catch finally implements extends new import package return instanceof"
      },
      contains: [ hljs.SHEBANG({
        binary: "groovy",
        relevance: 10
      }), COMMENT, STRING, REGEXP, NUMBER, {
        className: "class",
        beginKeywords: "class interface trait enum",
        end: /\{/,
        illegal: ":",
        contains: [ {
          beginKeywords: "extends implements"
        }, hljs.UNDERSCORE_TITLE_MODE ]
      }, {
        className: "meta",
        begin: "@[A-Za-z]+",
        relevance: 0
      }, {
        // highlight map keys and named parameters as attrs
        className: "attr",
        begin: IDENT_RE + "[ \t]*:"
      }, {
        // catch middle element of the ternary operator
        // to avoid highlight it as a label, named parameter, or map key
        begin: /\?/,
        end: /:/,
        relevance: 0,
        contains: [ COMMENT, STRING, REGEXP, NUMBER, "self" ]
      }, {
        // highlight labeled statements
        className: "symbol",
        begin: "^[ \t]*" + lookahead$2(IDENT_RE + ":"),
        excludeBegin: true,
        end: IDENT_RE + ":",
        relevance: 0
      } ],
      illegal: /#|<\//
    };
  }
  var groovy_1 = groovy;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$a(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function anyNumberOfTimes(re) {
    return concat$a("(", re, ")*");
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function optional$5(re) {
    return concat$a("(", re, ")?");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$a(...args) {
    const joined = args.map((x => source$a(x))).join("");
    return joined;
  }
  /**
   * Any of the passed expresssions may match
   *
   * Creates a huge this | this | that | that match
   * @param {(RegExp | string)[] } args
   * @returns {string}
   */  function either$1(...args) {
    const joined = "(" + args.map((x => source$a(x))).join("|") + ")";
    return joined;
  }
  /*
  Language: Handlebars
  Requires: xml.js
  Author: Robin Ward <robin.ward@gmail.com>
  Description: Matcher for Handlebars as well as EmberJS additions.
  Website: https://handlebarsjs.com
  Category: template
  */  function handlebars(hljs) {
    const BUILT_INS = {
      "builtin-name": [ "action", "bindattr", "collection", "component", "concat", "debugger", "each", "each-in", "get", "hash", "if", "in", "input", "link-to", "loc", "log", "lookup", "mut", "outlet", "partial", "query-params", "render", "template", "textarea", "unbound", "unless", "view", "with", "yield" ].join(" ")
    };
    const LITERALS = {
      literal: [ "true", "false", "undefined", "null" ].join(" ")
    };
    // as defined in https://handlebarsjs.com/guide/expressions.html#literal-segments
    // this regex matches literal segments like ' abc ' or [ abc ] as well as helpers and paths
    // like a/b, ./abc/cde, and abc.bcd
        const DOUBLE_QUOTED_ID_REGEX = /""|"[^"]+"/;
    const SINGLE_QUOTED_ID_REGEX = /''|'[^']+'/;
    const BRACKET_QUOTED_ID_REGEX = /\[\]|\[[^\]]+\]/;
    const PLAIN_ID_REGEX = /[^\s!"#%&'()*+,.\/;<=>@\[\\\]^`{|}~]+/;
    const PATH_DELIMITER_REGEX = /(\.|\/)/;
    const ANY_ID = either$1(DOUBLE_QUOTED_ID_REGEX, SINGLE_QUOTED_ID_REGEX, BRACKET_QUOTED_ID_REGEX, PLAIN_ID_REGEX);
    const IDENTIFIER_REGEX = concat$a(optional$5(/\.|\.\/|\//), // relative or absolute path
    ANY_ID, anyNumberOfTimes(concat$a(PATH_DELIMITER_REGEX, ANY_ID)));
    // identifier followed by a equal-sign (without the equal sign)
        const HASH_PARAM_REGEX = concat$a("(", BRACKET_QUOTED_ID_REGEX, "|", PLAIN_ID_REGEX, ")(?==)");
    const HELPER_NAME_OR_PATH_EXPRESSION = {
      begin: IDENTIFIER_REGEX,
      lexemes: /[\w.\/]+/
    };
    const HELPER_PARAMETER = hljs.inherit(HELPER_NAME_OR_PATH_EXPRESSION, {
      keywords: LITERALS
    });
    const SUB_EXPRESSION = {
      begin: /\(/,
      end: /\)/
    };
    const HASH = {
      // fka "attribute-assignment", parameters of the form 'key=value'
      className: "attr",
      begin: HASH_PARAM_REGEX,
      relevance: 0,
      starts: {
        begin: /=/,
        end: /=/,
        starts: {
          contains: [ hljs.NUMBER_MODE, hljs.QUOTE_STRING_MODE, hljs.APOS_STRING_MODE, HELPER_PARAMETER, SUB_EXPRESSION ]
        }
      }
    };
    const BLOCK_PARAMS = {
      // parameters of the form '{{#with x as | y |}}...{{/with}}'
      begin: /as\s+\|/,
      keywords: {
        keyword: "as"
      },
      end: /\|/,
      contains: [ {
        // define sub-mode in order to prevent highlighting of block-parameter named "as"
        begin: /\w+/
      } ]
    };
    const HELPER_PARAMETERS = {
      contains: [ hljs.NUMBER_MODE, hljs.QUOTE_STRING_MODE, hljs.APOS_STRING_MODE, BLOCK_PARAMS, HASH, HELPER_PARAMETER, SUB_EXPRESSION ],
      returnEnd: true
    };
    const SUB_EXPRESSION_CONTENTS = hljs.inherit(HELPER_NAME_OR_PATH_EXPRESSION, {
      className: "name",
      keywords: BUILT_INS,
      starts: hljs.inherit(HELPER_PARAMETERS, {
        end: /\)/
      })
    });
    SUB_EXPRESSION.contains = [ SUB_EXPRESSION_CONTENTS ];
    const OPENING_BLOCK_MUSTACHE_CONTENTS = hljs.inherit(HELPER_NAME_OR_PATH_EXPRESSION, {
      keywords: BUILT_INS,
      className: "name",
      starts: hljs.inherit(HELPER_PARAMETERS, {
        end: /\}\}/
      })
    });
    const CLOSING_BLOCK_MUSTACHE_CONTENTS = hljs.inherit(HELPER_NAME_OR_PATH_EXPRESSION, {
      keywords: BUILT_INS,
      className: "name"
    });
    const BASIC_MUSTACHE_CONTENTS = hljs.inherit(HELPER_NAME_OR_PATH_EXPRESSION, {
      className: "name",
      keywords: BUILT_INS,
      starts: hljs.inherit(HELPER_PARAMETERS, {
        end: /\}\}/
      })
    });
    const ESCAPE_MUSTACHE_WITH_PRECEEDING_BACKSLASH = {
      begin: /\\\{\{/,
      skip: true
    };
    const PREVENT_ESCAPE_WITH_ANOTHER_PRECEEDING_BACKSLASH = {
      begin: /\\\\(?=\{\{)/,
      skip: true
    };
    return {
      name: "Handlebars",
      aliases: [ "hbs", "html.hbs", "html.handlebars", "htmlbars" ],
      case_insensitive: true,
      subLanguage: "xml",
      contains: [ ESCAPE_MUSTACHE_WITH_PRECEEDING_BACKSLASH, PREVENT_ESCAPE_WITH_ANOTHER_PRECEEDING_BACKSLASH, hljs.COMMENT(/\{\{!--/, /--\}\}/), hljs.COMMENT(/\{\{!/, /\}\}/), {
        // open raw block "{{{{raw}}}} content not evaluated {{{{/raw}}}}"
        className: "template-tag",
        begin: /\{\{\{\{(?!\/)/,
        end: /\}\}\}\}/,
        contains: [ OPENING_BLOCK_MUSTACHE_CONTENTS ],
        starts: {
          end: /\{\{\{\{\//,
          returnEnd: true,
          subLanguage: "xml"
        }
      }, {
        // close raw block
        className: "template-tag",
        begin: /\{\{\{\{\//,
        end: /\}\}\}\}/,
        contains: [ CLOSING_BLOCK_MUSTACHE_CONTENTS ]
      }, {
        // open block statement
        className: "template-tag",
        begin: /\{\{#/,
        end: /\}\}/,
        contains: [ OPENING_BLOCK_MUSTACHE_CONTENTS ]
      }, {
        className: "template-tag",
        begin: /\{\{(?=else\}\})/,
        end: /\}\}/,
        keywords: "else"
      }, {
        className: "template-tag",
        begin: /\{\{(?=else if)/,
        end: /\}\}/,
        keywords: "else if"
      }, {
        // closing block statement
        className: "template-tag",
        begin: /\{\{\//,
        end: /\}\}/,
        contains: [ CLOSING_BLOCK_MUSTACHE_CONTENTS ]
      }, {
        // template variable or helper-call that is NOT html-escaped
        className: "template-variable",
        begin: /\{\{\{/,
        end: /\}\}\}/,
        contains: [ BASIC_MUSTACHE_CONTENTS ]
      }, {
        // template variable or helper-call that is html-escaped
        className: "template-variable",
        begin: /\{\{/,
        end: /\}\}/,
        contains: [ BASIC_MUSTACHE_CONTENTS ]
      } ]
    };
  }
  var handlebars_1 = handlebars;
  /*
  Language: Haskell
  Author: Jeremy Hull <sourdrums@gmail.com>
  Contributors: Zena Treep <zena.treep@gmail.com>
  Website: https://www.haskell.org
  Category: functional
  */  function haskell(hljs) {
    const COMMENT = {
      variants: [ hljs.COMMENT("--", "$"), hljs.COMMENT(/\{-/, /-\}/, {
        contains: [ "self" ]
      }) ]
    };
    const PRAGMA = {
      className: "meta",
      begin: /\{-#/,
      end: /#-\}/
    };
    const PREPROCESSOR = {
      className: "meta",
      begin: "^#",
      end: "$"
    };
    const CONSTRUCTOR = {
      className: "type",
      begin: "\\b[A-Z][\\w']*",
      // TODO: other constructors (build-in, infix).
      relevance: 0
    };
    const LIST = {
      begin: "\\(",
      end: "\\)",
      illegal: '"',
      contains: [ PRAGMA, PREPROCESSOR, {
        className: "type",
        begin: "\\b[A-Z][\\w]*(\\((\\.\\.|,|\\w+)\\))?"
      }, hljs.inherit(hljs.TITLE_MODE, {
        begin: "[_a-z][\\w']*"
      }), COMMENT ]
    };
    const RECORD = {
      begin: /\{/,
      end: /\}/,
      contains: LIST.contains
    };
    return {
      name: "Haskell",
      aliases: [ "hs" ],
      keywords: "let in if then else case of where do module import hiding " + "qualified type data newtype deriving class instance as default " + "infix infixl infixr foreign export ccall stdcall cplusplus " + "jvm dotnet safe unsafe family forall mdo proc rec",
      contains: [ 
      // Top-level constructions.
      {
        beginKeywords: "module",
        end: "where",
        keywords: "module where",
        contains: [ LIST, COMMENT ],
        illegal: "\\W\\.|;"
      }, {
        begin: "\\bimport\\b",
        end: "$",
        keywords: "import qualified as hiding",
        contains: [ LIST, COMMENT ],
        illegal: "\\W\\.|;"
      }, {
        className: "class",
        begin: "^(\\s*)?(class|instance)\\b",
        end: "where",
        keywords: "class family instance where",
        contains: [ CONSTRUCTOR, LIST, COMMENT ]
      }, {
        className: "class",
        begin: "\\b(data|(new)?type)\\b",
        end: "$",
        keywords: "data family type newtype deriving",
        contains: [ PRAGMA, CONSTRUCTOR, LIST, RECORD, COMMENT ]
      }, {
        beginKeywords: "default",
        end: "$",
        contains: [ CONSTRUCTOR, LIST, COMMENT ]
      }, {
        beginKeywords: "infix infixl infixr",
        end: "$",
        contains: [ hljs.C_NUMBER_MODE, COMMENT ]
      }, {
        begin: "\\bforeign\\b",
        end: "$",
        keywords: "foreign import export ccall stdcall cplusplus jvm " + "dotnet safe unsafe",
        contains: [ CONSTRUCTOR, hljs.QUOTE_STRING_MODE, COMMENT ]
      }, {
        className: "meta",
        begin: "#!\\/usr\\/bin\\/env runhaskell",
        end: "$"
      }, 
      // "Whitespaces".
      PRAGMA, PREPROCESSOR, 
      // Literals and names.
      // TODO: characters.
      hljs.QUOTE_STRING_MODE, hljs.C_NUMBER_MODE, CONSTRUCTOR, hljs.inherit(hljs.TITLE_MODE, {
        begin: "^[_a-z][\\w']*"
      }), COMMENT, {
        // No markup, relevance booster
        begin: "->|<-"
      } ]
    };
  }
  var haskell_1 = haskell;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$b(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function lookahead$3(re) {
    return concat$b("(?=", re, ")");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$b(...args) {
    const joined = args.map((x => source$b(x))).join("");
    return joined;
  }
  /**
   * Any of the passed expresssions may match
   *
   * Creates a huge this | this | that | that match
   * @param {(RegExp | string)[] } args
   * @returns {string}
   */  function either$2(...args) {
    const joined = "(" + args.map((x => source$b(x))).join("|") + ")";
    return joined;
  }
  /*
  Language: TOML, also INI
  Description: TOML aims to be a minimal configuration file format that's easy to read due to obvious semantics.
  Contributors: Guillaume Gomez <guillaume1.gomez@gmail.com>
  Category: common, config
  Website: https://github.com/toml-lang/toml
  */  function ini(hljs) {
    const NUMBERS = {
      className: "number",
      relevance: 0,
      variants: [ {
        begin: /([+-]+)?[\d]+_[\d_]+/
      }, {
        begin: hljs.NUMBER_RE
      } ]
    };
    const COMMENTS = hljs.COMMENT();
    COMMENTS.variants = [ {
      begin: /;/,
      end: /$/
    }, {
      begin: /#/,
      end: /$/
    } ];
    const VARIABLES = {
      className: "variable",
      variants: [ {
        begin: /\$[\w\d"][\w\d_]*/
      }, {
        begin: /\$\{(.*?)\}/
      } ]
    };
    const LITERALS = {
      className: "literal",
      begin: /\bon|off|true|false|yes|no\b/
    };
    const STRINGS = {
      className: "string",
      contains: [ hljs.BACKSLASH_ESCAPE ],
      variants: [ {
        begin: "'''",
        end: "'''",
        relevance: 10
      }, {
        begin: '"""',
        end: '"""',
        relevance: 10
      }, {
        begin: '"',
        end: '"'
      }, {
        begin: "'",
        end: "'"
      } ]
    };
    const ARRAY = {
      begin: /\[/,
      end: /\]/,
      contains: [ COMMENTS, LITERALS, VARIABLES, STRINGS, NUMBERS, "self" ],
      relevance: 0
    };
    const BARE_KEY = /[A-Za-z0-9_-]+/;
    const QUOTED_KEY_DOUBLE_QUOTE = /"(\\"|[^"])*"/;
    const QUOTED_KEY_SINGLE_QUOTE = /'[^']*'/;
    const ANY_KEY = either$2(BARE_KEY, QUOTED_KEY_DOUBLE_QUOTE, QUOTED_KEY_SINGLE_QUOTE);
    const DOTTED_KEY = concat$b(ANY_KEY, "(\\s*\\.\\s*", ANY_KEY, ")*", lookahead$3(/\s*=\s*[^#\s]/));
    return {
      name: "TOML, also INI",
      aliases: [ "toml" ],
      case_insensitive: true,
      illegal: /\S/,
      contains: [ COMMENTS, {
        className: "section",
        begin: /\[+/,
        end: /\]+/
      }, {
        begin: DOTTED_KEY,
        className: "attr",
        starts: {
          end: /$/,
          contains: [ COMMENTS, ARRAY, LITERALS, VARIABLES, STRINGS, NUMBERS ]
        }
      } ]
    };
  }
  var ini_1 = ini;
  // https://docs.oracle.com/javase/specs/jls/se15/html/jls-3.html#jls-3.10
    var decimalDigits = "[0-9](_*[0-9])*";
  var frac = `\\.(${decimalDigits})`;
  var hexDigits = "[0-9a-fA-F](_*[0-9a-fA-F])*";
  var NUMERIC = {
    className: "number",
    variants: [ 
    // DecimalFloatingPointLiteral
    // including ExponentPart
    {
      begin: `(\\b(${decimalDigits})((${frac})|\\.)?|(${frac}))` + `[eE][+-]?(${decimalDigits})[fFdD]?\\b`
    }, 
    // excluding ExponentPart
    {
      begin: `\\b(${decimalDigits})((${frac})[fFdD]?\\b|\\.([fFdD]\\b)?)`
    }, {
      begin: `(${frac})[fFdD]?\\b`
    }, {
      begin: `\\b(${decimalDigits})[fFdD]\\b`
    }, 
    // HexadecimalFloatingPointLiteral
    {
      begin: `\\b0[xX]((${hexDigits})\\.?|(${hexDigits})?\\.(${hexDigits}))` + `[pP][+-]?(${decimalDigits})[fFdD]?\\b`
    }, 
    // DecimalIntegerLiteral
    {
      begin: "\\b(0|[1-9](_*[0-9])*)[lL]?\\b"
    }, 
    // HexIntegerLiteral
    {
      begin: `\\b0[xX](${hexDigits})[lL]?\\b`
    }, 
    // OctalIntegerLiteral
    {
      begin: "\\b0(_*[0-7])*[lL]?\\b"
    }, 
    // BinaryIntegerLiteral
    {
      begin: "\\b0[bB][01](_*[01])*[lL]?\\b"
    } ],
    relevance: 0
  };
  /*
  Language: Java
  Author: Vsevolod Solovyov <vsevolod.solovyov@gmail.com>
  Category: common, enterprise
  Website: https://www.java.com/
  */  function java(hljs) {
    var JAVA_IDENT_RE = "[\xc0-\u02b8a-zA-Z_$][\xc0-\u02b8a-zA-Z_$0-9]*";
    var GENERIC_IDENT_RE = JAVA_IDENT_RE + "(<" + JAVA_IDENT_RE + "(\\s*,\\s*" + JAVA_IDENT_RE + ")*>)?";
    var KEYWORDS = "false synchronized int abstract float private char boolean var static null if const " + "for true while long strictfp finally protected import native final void " + "enum else break transient catch instanceof byte super volatile case assert short " + "package default double public try this switch continue throws protected public private " + "module requires exports do";
    var ANNOTATION = {
      className: "meta",
      begin: "@" + JAVA_IDENT_RE,
      contains: [ {
        begin: /\(/,
        end: /\)/,
        contains: [ "self" ]
      } ]
    };
    const NUMBER = NUMERIC;
    return {
      name: "Java",
      aliases: [ "jsp" ],
      keywords: KEYWORDS,
      illegal: /<\/|#/,
      contains: [ hljs.COMMENT("/\\*\\*", "\\*/", {
        relevance: 0,
        contains: [ {
          // eat up @'s in emails to prevent them to be recognized as doctags
          begin: /\w+@/,
          relevance: 0
        }, {
          className: "doctag",
          begin: "@[A-Za-z]+"
        } ]
      }), 
      // relevance boost
      {
        begin: /import java\.[a-z]+\./,
        keywords: "import",
        relevance: 2
      }, hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, {
        className: "class",
        beginKeywords: "class interface enum",
        end: /[{;=]/,
        excludeEnd: true,
        keywords: "class interface enum",
        illegal: /[:"\[\]]/,
        contains: [ {
          beginKeywords: "extends implements"
        }, hljs.UNDERSCORE_TITLE_MODE ]
      }, {
        // Expression keywords prevent 'keyword Name(...)' from being
        // recognized as a function definition
        beginKeywords: "new throw return else",
        relevance: 0
      }, {
        className: "class",
        begin: "record\\s+" + hljs.UNDERSCORE_IDENT_RE + "\\s*\\(",
        returnBegin: true,
        excludeEnd: true,
        end: /[{;=]/,
        keywords: KEYWORDS,
        contains: [ {
          beginKeywords: "record"
        }, {
          begin: hljs.UNDERSCORE_IDENT_RE + "\\s*\\(",
          returnBegin: true,
          relevance: 0,
          contains: [ hljs.UNDERSCORE_TITLE_MODE ]
        }, {
          className: "params",
          begin: /\(/,
          end: /\)/,
          keywords: KEYWORDS,
          relevance: 0,
          contains: [ hljs.C_BLOCK_COMMENT_MODE ]
        }, hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE ]
      }, {
        className: "function",
        begin: "(" + GENERIC_IDENT_RE + "\\s+)+" + hljs.UNDERSCORE_IDENT_RE + "\\s*\\(",
        returnBegin: true,
        end: /[{;=]/,
        excludeEnd: true,
        keywords: KEYWORDS,
        contains: [ {
          begin: hljs.UNDERSCORE_IDENT_RE + "\\s*\\(",
          returnBegin: true,
          relevance: 0,
          contains: [ hljs.UNDERSCORE_TITLE_MODE ]
        }, {
          className: "params",
          begin: /\(/,
          end: /\)/,
          keywords: KEYWORDS,
          relevance: 0,
          contains: [ ANNOTATION, hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, NUMBER, hljs.C_BLOCK_COMMENT_MODE ]
        }, hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE ]
      }, NUMBER, ANNOTATION ]
    };
  }
  var java_1 = java;
  const IDENT_RE$1 = "[A-Za-z$_][0-9A-Za-z$_]*";
  const KEYWORDS$1 = [ "as", // for exports
  "in", "of", "if", "for", "while", "finally", "var", "new", "function", "do", "return", "void", "else", "break", "catch", "instanceof", "with", "throw", "case", "default", "try", "switch", "continue", "typeof", "delete", "let", "yield", "const", "class", 
  // JS handles these with a special rule
  // "get",
  // "set",
  "debugger", "async", "await", "static", "import", "from", "export", "extends" ];
  const LITERALS$1 = [ "true", "false", "null", "undefined", "NaN", "Infinity" ];
  const TYPES$1 = [ "Intl", "DataView", "Number", "Math", "Date", "String", "RegExp", "Object", "Function", "Boolean", "Error", "Symbol", "Set", "Map", "WeakSet", "WeakMap", "Proxy", "Reflect", "JSON", "Promise", "Float64Array", "Int16Array", "Int32Array", "Int8Array", "Uint16Array", "Uint32Array", "Float32Array", "Array", "Uint8Array", "Uint8ClampedArray", "ArrayBuffer" ];
  const ERROR_TYPES$1 = [ "EvalError", "InternalError", "RangeError", "ReferenceError", "SyntaxError", "TypeError", "URIError" ];
  const BUILT_IN_GLOBALS$1 = [ "setInterval", "setTimeout", "clearInterval", "clearTimeout", "require", "exports", "eval", "isFinite", "isNaN", "parseFloat", "parseInt", "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent", "escape", "unescape" ];
  const BUILT_IN_VARIABLES$1 = [ "arguments", "this", "super", "console", "window", "document", "localStorage", "module", "global" ];
  const BUILT_INS$1 = [].concat(BUILT_IN_GLOBALS$1, BUILT_IN_VARIABLES$1, TYPES$1, ERROR_TYPES$1);
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$c(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function lookahead$4(re) {
    return concat$c("(?=", re, ")");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$c(...args) {
    const joined = args.map((x => source$c(x))).join("");
    return joined;
  }
  /*
  Language: JavaScript
  Description: JavaScript (JS) is a lightweight, interpreted, or just-in-time compiled programming language with first-class functions.
  Category: common, scripting
  Website: https://developer.mozilla.org/en-US/docs/Web/JavaScript
  */
  /** @type LanguageFn */  function javascript(hljs) {
    /**
     * Takes a string like "<Booger" and checks to see
     * if we can find a matching "</Booger" later in the
     * content.
     * @param {RegExpMatchArray} match
     * @param {{after:number}} param1
     */
    const hasClosingTag = (match, {after: after}) => {
      const tag = "</" + match[0].slice(1);
      const pos = match.input.indexOf(tag, after);
      return pos !== -1;
    };
    const IDENT_RE$1$1 = IDENT_RE$1;
    const FRAGMENT = {
      begin: "<>",
      end: "</>"
    };
    const XML_TAG = {
      begin: /<[A-Za-z0-9\\._:-]+/,
      end: /\/[A-Za-z0-9\\._:-]+>|\/>/,
      /**
       * @param {RegExpMatchArray} match
       * @param {CallbackResponse} response
       */
      isTrulyOpeningTag: (match, response) => {
        const afterMatchIndex = match[0].length + match.index;
        const nextChar = match.input[afterMatchIndex];
        // nested type?
        // HTML should not include another raw `<` inside a tag
        // But a type might: `<Array<Array<number>>`, etc.
                if (nextChar === "<") {
          response.ignoreMatch();
          return;
        }
        // <something>
        // This is now either a tag or a type.
                if (nextChar === ">") {
          // if we cannot find a matching closing tag, then we
          // will ignore it
          if (!hasClosingTag(match, {
            after: afterMatchIndex
          })) {
            response.ignoreMatch();
          }
        }
      }
    };
    const KEYWORDS$1$1 = {
      $pattern: IDENT_RE$1,
      keyword: KEYWORDS$1.join(" "),
      literal: LITERALS$1.join(" "),
      built_in: BUILT_INS$1.join(" ")
    };
    // https://tc39.es/ecma262/#sec-literals-numeric-literals
        const decimalDigits = "[0-9](_?[0-9])*";
    const frac = `\\.(${decimalDigits})`;
    // DecimalIntegerLiteral, including Annex B NonOctalDecimalIntegerLiteral
    // https://tc39.es/ecma262/#sec-additional-syntax-numeric-literals
        const decimalInteger = `0|[1-9](_?[0-9])*|0[0-7]*[89][0-9]*`;
    const NUMBER = {
      className: "number",
      variants: [ 
      // DecimalLiteral
      {
        begin: `(\\b(${decimalInteger})((${frac})|\\.)?|(${frac}))` + `[eE][+-]?(${decimalDigits})\\b`
      }, {
        begin: `\\b(${decimalInteger})\\b((${frac})\\b|\\.)?|(${frac})\\b`
      }, 
      // DecimalBigIntegerLiteral
      {
        begin: `\\b(0|[1-9](_?[0-9])*)n\\b`
      }, 
      // NonDecimalIntegerLiteral
      {
        begin: "\\b0[xX][0-9a-fA-F](_?[0-9a-fA-F])*n?\\b"
      }, {
        begin: "\\b0[bB][0-1](_?[0-1])*n?\\b"
      }, {
        begin: "\\b0[oO][0-7](_?[0-7])*n?\\b"
      }, 
      // LegacyOctalIntegerLiteral (does not include underscore separators)
      // https://tc39.es/ecma262/#sec-additional-syntax-numeric-literals
      {
        begin: "\\b0[0-7]+n?\\b"
      } ],
      relevance: 0
    };
    const SUBST = {
      className: "subst",
      begin: "\\$\\{",
      end: "\\}",
      keywords: KEYWORDS$1$1,
      contains: []
    };
    const HTML_TEMPLATE = {
      begin: "html`",
      end: "",
      starts: {
        end: "`",
        returnEnd: false,
        contains: [ hljs.BACKSLASH_ESCAPE, SUBST ],
        subLanguage: "xml"
      }
    };
    const CSS_TEMPLATE = {
      begin: "css`",
      end: "",
      starts: {
        end: "`",
        returnEnd: false,
        contains: [ hljs.BACKSLASH_ESCAPE, SUBST ],
        subLanguage: "css"
      }
    };
    const TEMPLATE_STRING = {
      className: "string",
      begin: "`",
      end: "`",
      contains: [ hljs.BACKSLASH_ESCAPE, SUBST ]
    };
    const JSDOC_COMMENT = hljs.COMMENT("/\\*\\*", "\\*/", {
      relevance: 0,
      contains: [ {
        className: "doctag",
        begin: "@[A-Za-z]+",
        contains: [ {
          className: "type",
          begin: "\\{",
          end: "\\}",
          relevance: 0
        }, {
          className: "variable",
          begin: IDENT_RE$1$1 + "(?=\\s*(-)|$)",
          endsParent: true,
          relevance: 0
        }, 
        // eat spaces (not newlines) so we can find
        // types or variables
        {
          begin: /(?=[^\n])\s/,
          relevance: 0
        } ]
      } ]
    });
    const COMMENT = {
      className: "comment",
      variants: [ JSDOC_COMMENT, hljs.C_BLOCK_COMMENT_MODE, hljs.C_LINE_COMMENT_MODE ]
    };
    const SUBST_INTERNALS = [ hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, HTML_TEMPLATE, CSS_TEMPLATE, TEMPLATE_STRING, NUMBER, hljs.REGEXP_MODE ];
    SUBST.contains = SUBST_INTERNALS.concat({
      // we need to pair up {} inside our subst to prevent
      // it from ending too early by matching another }
      begin: /\{/,
      end: /\}/,
      keywords: KEYWORDS$1$1,
      contains: [ "self" ].concat(SUBST_INTERNALS)
    });
    const SUBST_AND_COMMENTS = [].concat(COMMENT, SUBST.contains);
    const PARAMS_CONTAINS = SUBST_AND_COMMENTS.concat([ 
    // eat recursive parens in sub expressions
    {
      begin: /\(/,
      end: /\)/,
      keywords: KEYWORDS$1$1,
      contains: [ "self" ].concat(SUBST_AND_COMMENTS)
    } ]);
    const PARAMS = {
      className: "params",
      begin: /\(/,
      end: /\)/,
      excludeBegin: true,
      excludeEnd: true,
      keywords: KEYWORDS$1$1,
      contains: PARAMS_CONTAINS
    };
    return {
      name: "Javascript",
      aliases: [ "js", "jsx", "mjs", "cjs" ],
      keywords: KEYWORDS$1$1,
      // this will be extended by TypeScript
      exports: {
        PARAMS_CONTAINS: PARAMS_CONTAINS
      },
      illegal: /#(?![$_A-z])/,
      contains: [ hljs.SHEBANG({
        label: "shebang",
        binary: "node",
        relevance: 5
      }), {
        label: "use_strict",
        className: "meta",
        relevance: 10,
        begin: /^\s*['"]use (strict|asm)['"]/
      }, hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, HTML_TEMPLATE, CSS_TEMPLATE, TEMPLATE_STRING, COMMENT, NUMBER, {
        // object attr container
        begin: concat$c(/[{,\n]\s*/, 
        // we need to look ahead to make sure that we actually have an
        // attribute coming up so we don't steal a comma from a potential
        // "value" container
        // NOTE: this might not work how you think.  We don't actually always
        // enter this mode and stay.  Instead it might merely match `,
        // <comments up next>` and then immediately end after the , because it
        // fails to find any actual attrs. But this still does the job because
        // it prevents the value contain rule from grabbing this instead and
        // prevening this rule from firing when we actually DO have keys.
        lookahead$4(concat$c(
        // we also need to allow for multiple possible comments inbetween
        // the first key:value pairing
        /(((\/\/.*$)|(\/\*(\*[^/]|[^*])*\*\/))\s*)*/, IDENT_RE$1$1 + "\\s*:"))),
        relevance: 0,
        contains: [ {
          className: "attr",
          begin: IDENT_RE$1$1 + lookahead$4("\\s*:"),
          relevance: 0
        } ]
      }, {
        // "value" container
        begin: "(" + hljs.RE_STARTERS_RE + "|\\b(case|return|throw)\\b)\\s*",
        keywords: "return throw case",
        contains: [ COMMENT, hljs.REGEXP_MODE, {
          className: "function",
          // we have to count the parens to make sure we actually have the
          // correct bounding ( ) before the =>.  There could be any number of
          // sub-expressions inside also surrounded by parens.
          begin: "(\\(" + "[^()]*(\\(" + "[^()]*(\\(" + "[^()]*" + "\\)[^()]*)*" + "\\)[^()]*)*" + "\\)|" + hljs.UNDERSCORE_IDENT_RE + ")\\s*=>",
          returnBegin: true,
          end: "\\s*=>",
          contains: [ {
            className: "params",
            variants: [ {
              begin: hljs.UNDERSCORE_IDENT_RE,
              relevance: 0
            }, {
              className: null,
              begin: /\(\s*\)/,
              skip: true
            }, {
              begin: /\(/,
              end: /\)/,
              excludeBegin: true,
              excludeEnd: true,
              keywords: KEYWORDS$1$1,
              contains: PARAMS_CONTAINS
            } ]
          } ]
        }, {
          // could be a comma delimited list of params to a function call
          begin: /,/,
          relevance: 0
        }, {
          className: "",
          begin: /\s/,
          end: /\s*/,
          skip: true
        }, {
          // JSX
          variants: [ {
            begin: FRAGMENT.begin,
            end: FRAGMENT.end
          }, {
            begin: XML_TAG.begin,
            // we carefully check the opening tag to see if it truly
            // is a tag and not a false positive
            "on:begin": XML_TAG.isTrulyOpeningTag,
            end: XML_TAG.end
          } ],
          subLanguage: "xml",
          contains: [ {
            begin: XML_TAG.begin,
            end: XML_TAG.end,
            skip: true,
            contains: [ "self" ]
          } ]
        } ],
        relevance: 0
      }, {
        className: "function",
        beginKeywords: "function",
        end: /[{;]/,
        excludeEnd: true,
        keywords: KEYWORDS$1$1,
        contains: [ "self", hljs.inherit(hljs.TITLE_MODE, {
          begin: IDENT_RE$1$1
        }), PARAMS ],
        illegal: /%/
      }, {
        // prevent this from getting swallowed up by function
        // since they appear "function like"
        beginKeywords: "while if switch catch for"
      }, {
        className: "function",
        // we have to count the parens to make sure we actually have the correct
        // bounding ( ).  There could be any number of sub-expressions inside
        // also surrounded by parens.
        begin: hljs.UNDERSCORE_IDENT_RE + "\\(" + // first parens
        "[^()]*(\\(" + "[^()]*(\\(" + "[^()]*" + "\\)[^()]*)*" + "\\)[^()]*)*" + "\\)\\s*\\{",
        // end parens
        returnBegin: true,
        contains: [ PARAMS, hljs.inherit(hljs.TITLE_MODE, {
          begin: IDENT_RE$1$1
        }) ]
      }, 
      // hack: prevents detection of keywords in some circumstances
      // .keyword()
      // $keyword = x
      {
        variants: [ {
          begin: "\\." + IDENT_RE$1$1
        }, {
          begin: "\\$" + IDENT_RE$1$1
        } ],
        relevance: 0
      }, {
        // ES6 class
        className: "class",
        beginKeywords: "class",
        end: /[{;=]/,
        excludeEnd: true,
        illegal: /[:"[\]]/,
        contains: [ {
          beginKeywords: "extends"
        }, hljs.UNDERSCORE_TITLE_MODE ]
      }, {
        begin: /\b(?=constructor)/,
        end: /[{;]/,
        excludeEnd: true,
        contains: [ hljs.inherit(hljs.TITLE_MODE, {
          begin: IDENT_RE$1$1
        }), "self", PARAMS ]
      }, {
        begin: "(get|set)\\s+(?=" + IDENT_RE$1$1 + "\\()",
        end: /\{/,
        keywords: "get set",
        contains: [ hljs.inherit(hljs.TITLE_MODE, {
          begin: IDENT_RE$1$1
        }), {
          begin: /\(\)/
        }, // eat to avoid empty params
        PARAMS ]
      }, {
        begin: /\$[(.]/
      } ]
    };
  }
  var javascript_1 = javascript;
  /*
  Language: JSON
  Description: JSON (JavaScript Object Notation) is a lightweight data-interchange format.
  Author: Ivan Sagalaev <maniac@softwaremaniacs.org>
  Website: http://www.json.org
  Category: common, protocols
  */  function json(hljs) {
    const LITERALS = {
      literal: "true false null"
    };
    const ALLOWED_COMMENTS = [ hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE ];
    const TYPES = [ hljs.QUOTE_STRING_MODE, hljs.C_NUMBER_MODE ];
    const VALUE_CONTAINER = {
      end: ",",
      endsWithParent: true,
      excludeEnd: true,
      contains: TYPES,
      keywords: LITERALS
    };
    const OBJECT = {
      begin: /\{/,
      end: /\}/,
      contains: [ {
        className: "attr",
        begin: /"/,
        end: /"/,
        contains: [ hljs.BACKSLASH_ESCAPE ],
        illegal: "\\n"
      }, hljs.inherit(VALUE_CONTAINER, {
        begin: /:/
      }) ].concat(ALLOWED_COMMENTS),
      illegal: "\\S"
    };
    const ARRAY = {
      begin: "\\[",
      end: "\\]",
      contains: [ hljs.inherit(VALUE_CONTAINER) ],
      // inherit is a workaround for a bug that makes shared modes with endsWithParent compile only the ending of one of the parents
      illegal: "\\S"
    };
    TYPES.push(OBJECT, ARRAY);
    ALLOWED_COMMENTS.forEach((function(rule) {
      TYPES.push(rule);
    }));
    return {
      name: "JSON",
      contains: TYPES,
      keywords: LITERALS,
      illegal: "\\S"
    };
  }
  var json_1 = json;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$d(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * Any of the passed expresssions may match
   *
   * Creates a huge this | this | that | that match
   * @param {(RegExp | string)[] } args
   * @returns {string}
   */  function either$3(...args) {
    const joined = "(" + args.map((x => source$d(x))).join("|") + ")";
    return joined;
  }
  /*
  Language: LaTeX
  Author: Benedikt Wilde <bwilde@posteo.de>
  Website: https://www.latex-project.org
  Category: markup
  */
  /** @type LanguageFn */  function latex(hljs) {
    const KNOWN_CONTROL_WORDS = either$3(...[ "(?:NeedsTeXFormat|RequirePackage|GetIdInfo)", "Provides(?:Expl)?(?:Package|Class|File)", "(?:DeclareOption|ProcessOptions)", "(?:documentclass|usepackage|input|include)", "makeat(?:letter|other)", "ExplSyntax(?:On|Off)", "(?:new|renew|provide)?command", "(?:re)newenvironment", "(?:New|Renew|Provide|Declare)(?:Expandable)?DocumentCommand", "(?:New|Renew|Provide|Declare)DocumentEnvironment", "(?:(?:e|g|x)?def|let)", "(?:begin|end)", "(?:part|chapter|(?:sub){0,2}section|(?:sub)?paragraph)", "caption", "(?:label|(?:eq|page|name)?ref|(?:paren|foot|super)?cite)", "(?:alpha|beta|[Gg]amma|[Dd]elta|(?:var)?epsilon|zeta|eta|[Tt]heta|vartheta)", "(?:iota|(?:var)?kappa|[Ll]ambda|mu|nu|[Xx]i|[Pp]i|varpi|(?:var)rho)", "(?:[Ss]igma|varsigma|tau|[Uu]psilon|[Pp]hi|varphi|chi|[Pp]si|[Oo]mega)", "(?:frac|sum|prod|lim|infty|times|sqrt|leq|geq|left|right|middle|[bB]igg?)", "(?:[lr]angle|q?quad|[lcvdi]?dots|d?dot|hat|tilde|bar)" ].map((word => word + "(?![a-zA-Z@:_])")));
    const L3_REGEX = new RegExp([ 
    // A function \module_function_name:signature or \__module_function_name:signature,
    // where both module and function_name need at least two characters and
    // function_name may contain single underscores.
    "(?:__)?[a-zA-Z]{2,}_[a-zA-Z](?:_?[a-zA-Z])+:[a-zA-Z]*", 
    // A variable \scope_module_and_name_type or \scope__module_ane_name_type,
    // where scope is one of l, g or c, type needs at least two characters
    // and module_and_name may contain single underscores.
    "[lgc]__?[a-zA-Z](?:_?[a-zA-Z])*_[a-zA-Z]{2,}", 
    // A quark \q_the_name or \q__the_name or
    // scan mark \s_the_name or \s__vthe_name,
    // where variable_name needs at least two characters and
    // may contain single underscores.
    "[qs]__?[a-zA-Z](?:_?[a-zA-Z])+", 
    // Other LaTeX3 macro names that are not covered by the three rules above.
    "use(?:_i)?:[a-zA-Z]*", "(?:else|fi|or):", "(?:if|cs|exp):w", "(?:hbox|vbox):n", "::[a-zA-Z]_unbraced", "::[a-zA-Z:]" ].map((pattern => pattern + "(?![a-zA-Z:_])")).join("|"));
    const L2_VARIANTS = [ {
      begin: /[a-zA-Z@]+/
    }, // control word
    {
      begin: /[^a-zA-Z@]?/
    } ];
    const DOUBLE_CARET_VARIANTS = [ {
      begin: /\^{6}[0-9a-f]{6}/
    }, {
      begin: /\^{5}[0-9a-f]{5}/
    }, {
      begin: /\^{4}[0-9a-f]{4}/
    }, {
      begin: /\^{3}[0-9a-f]{3}/
    }, {
      begin: /\^{2}[0-9a-f]{2}/
    }, {
      begin: /\^{2}[\u0000-\u007f]/
    } ];
    const CONTROL_SEQUENCE = {
      className: "keyword",
      begin: /\\/,
      relevance: 0,
      contains: [ {
        endsParent: true,
        begin: KNOWN_CONTROL_WORDS
      }, {
        endsParent: true,
        begin: L3_REGEX
      }, {
        endsParent: true,
        variants: DOUBLE_CARET_VARIANTS
      }, {
        endsParent: true,
        relevance: 0,
        variants: L2_VARIANTS
      } ]
    };
    const MACRO_PARAM = {
      className: "params",
      relevance: 0,
      begin: /#+\d?/
    };
    const DOUBLE_CARET_CHAR = {
      // relevance: 1
      variants: DOUBLE_CARET_VARIANTS
    };
    const SPECIAL_CATCODE = {
      className: "built_in",
      relevance: 0,
      begin: /[$&^_]/
    };
    const MAGIC_COMMENT = {
      className: "meta",
      begin: "% !TeX",
      end: "$",
      relevance: 10
    };
    const COMMENT = hljs.COMMENT("%", "$", {
      relevance: 0
    });
    const EVERYTHING_BUT_VERBATIM = [ CONTROL_SEQUENCE, MACRO_PARAM, DOUBLE_CARET_CHAR, SPECIAL_CATCODE, MAGIC_COMMENT, COMMENT ];
    const BRACE_GROUP_NO_VERBATIM = {
      begin: /\{/,
      end: /\}/,
      relevance: 0,
      contains: [ "self", ...EVERYTHING_BUT_VERBATIM ]
    };
    const ARGUMENT_BRACES = hljs.inherit(BRACE_GROUP_NO_VERBATIM, {
      relevance: 0,
      endsParent: true,
      contains: [ BRACE_GROUP_NO_VERBATIM, ...EVERYTHING_BUT_VERBATIM ]
    });
    const ARGUMENT_BRACKETS = {
      begin: /\[/,
      end: /\]/,
      endsParent: true,
      relevance: 0,
      contains: [ BRACE_GROUP_NO_VERBATIM, ...EVERYTHING_BUT_VERBATIM ]
    };
    const SPACE_GOBBLER = {
      begin: /\s+/,
      relevance: 0
    };
    const ARGUMENT_M = [ ARGUMENT_BRACES ];
    const ARGUMENT_O = [ ARGUMENT_BRACKETS ];
    const ARGUMENT_AND_THEN = function(arg, starts_mode) {
      return {
        contains: [ SPACE_GOBBLER ],
        starts: {
          relevance: 0,
          contains: arg,
          starts: starts_mode
        }
      };
    };
    const CSNAME = function(csname, starts_mode) {
      return {
        begin: "\\\\" + csname + "(?![a-zA-Z@:_])",
        keywords: {
          $pattern: /\\[a-zA-Z]+/,
          keyword: "\\" + csname
        },
        relevance: 0,
        contains: [ SPACE_GOBBLER ],
        starts: starts_mode
      };
    };
    const BEGIN_ENV = function(envname, starts_mode) {
      return hljs.inherit({
        begin: "\\\\begin(?=[ \t]*(\\r?\\n[ \t]*)?\\{" + envname + "\\})",
        keywords: {
          $pattern: /\\[a-zA-Z]+/,
          keyword: "\\begin"
        },
        relevance: 0
      }, ARGUMENT_AND_THEN(ARGUMENT_M, starts_mode));
    };
    const VERBATIM_DELIMITED_EQUAL = (innerName = "string") => hljs.END_SAME_AS_BEGIN({
      className: innerName,
      begin: /(.|\r?\n)/,
      end: /(.|\r?\n)/,
      excludeBegin: true,
      excludeEnd: true,
      endsParent: true
    });
    const VERBATIM_DELIMITED_ENV = function(envname) {
      return {
        className: "string",
        end: "(?=\\\\end\\{" + envname + "\\})"
      };
    };
    const VERBATIM_DELIMITED_BRACES = (innerName = "string") => ({
      relevance: 0,
      begin: /\{/,
      starts: {
        endsParent: true,
        contains: [ {
          className: innerName,
          end: /(?=\})/,
          endsParent: true,
          contains: [ {
            begin: /\{/,
            end: /\}/,
            relevance: 0,
            contains: [ "self" ]
          } ]
        } ]
      }
    });
    const VERBATIM = [ ...[ "verb", "lstinline" ].map((csname => CSNAME(csname, {
      contains: [ VERBATIM_DELIMITED_EQUAL() ]
    }))), CSNAME("mint", ARGUMENT_AND_THEN(ARGUMENT_M, {
      contains: [ VERBATIM_DELIMITED_EQUAL() ]
    })), CSNAME("mintinline", ARGUMENT_AND_THEN(ARGUMENT_M, {
      contains: [ VERBATIM_DELIMITED_BRACES(), VERBATIM_DELIMITED_EQUAL() ]
    })), CSNAME("url", {
      contains: [ VERBATIM_DELIMITED_BRACES("link"), VERBATIM_DELIMITED_BRACES("link") ]
    }), CSNAME("hyperref", {
      contains: [ VERBATIM_DELIMITED_BRACES("link") ]
    }), CSNAME("href", ARGUMENT_AND_THEN(ARGUMENT_O, {
      contains: [ VERBATIM_DELIMITED_BRACES("link") ]
    })), ...[].concat(...[ "", "\\*" ].map((suffix => [ BEGIN_ENV("verbatim" + suffix, VERBATIM_DELIMITED_ENV("verbatim" + suffix)), BEGIN_ENV("filecontents" + suffix, ARGUMENT_AND_THEN(ARGUMENT_M, VERBATIM_DELIMITED_ENV("filecontents" + suffix))), ...[ "", "B", "L" ].map((prefix => BEGIN_ENV(prefix + "Verbatim" + suffix, ARGUMENT_AND_THEN(ARGUMENT_O, VERBATIM_DELIMITED_ENV(prefix + "Verbatim" + suffix))))) ]))), BEGIN_ENV("minted", ARGUMENT_AND_THEN(ARGUMENT_O, ARGUMENT_AND_THEN(ARGUMENT_M, VERBATIM_DELIMITED_ENV("minted")))) ];
    return {
      name: "LaTeX",
      aliases: [ "TeX" ],
      contains: [ ...VERBATIM, ...EVERYTHING_BUT_VERBATIM ]
    };
  }
  var latex_1 = latex;
  /*
  Language: Less
  Description: It's CSS, with just a little more.
  Author:   Max Mikhailov <seven.phases.max@gmail.com>
  Website: http://lesscss.org
  Category: common, css
  */  function less(hljs) {
    var IDENT_RE = "[\\w-]+";
 // yes, Less identifiers may begin with a digit
        var INTERP_IDENT_RE = "(" + IDENT_RE + "|@\\{" + IDENT_RE + "\\})";
    /* Generic Modes */    var RULES = [], VALUE = [];
 // forward def. for recursive modes
        var STRING_MODE = function(c) {
      return {
        // Less strings are not multiline (also include '~' for more consistent coloring of "escaped" strings)
        className: "string",
        begin: "~?" + c + ".*?" + c
      };
    };
    var IDENT_MODE = function(name, begin, relevance) {
      return {
        className: name,
        begin: begin,
        relevance: relevance
      };
    };
    var PARENS_MODE = {
      // used only to properly balance nested parens inside mixin call, def. arg list
      begin: "\\(",
      end: "\\)",
      contains: VALUE,
      relevance: 0
    };
    // generic Less highlighter (used almost everywhere except selectors):
        VALUE.push(hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, STRING_MODE("'"), STRING_MODE('"'), hljs.CSS_NUMBER_MODE, // fixme: it does not include dot for numbers like .5em :(
    {
      begin: "(url|data-uri)\\(",
      starts: {
        className: "string",
        end: "[\\)\\n]",
        excludeEnd: true
      }
    }, IDENT_MODE("number", "#[0-9A-Fa-f]+\\b"), PARENS_MODE, IDENT_MODE("variable", "@@?" + IDENT_RE, 10), IDENT_MODE("variable", "@\\{" + IDENT_RE + "\\}"), IDENT_MODE("built_in", "~?`[^`]*?`"), // inline javascript (or whatever host language) *multiline* string
    {
      // @media features (it’s here to not duplicate things in AT_RULE_MODE with extra PARENS_MODE overriding):
      className: "attribute",
      begin: IDENT_RE + "\\s*:",
      end: ":",
      returnBegin: true,
      excludeEnd: true
    }, {
      className: "meta",
      begin: "!important"
    });
    var VALUE_WITH_RULESETS = VALUE.concat({
      begin: /\{/,
      end: /\}/,
      contains: RULES
    });
    var MIXIN_GUARD_MODE = {
      beginKeywords: "when",
      endsWithParent: true,
      contains: [ {
        beginKeywords: "and not"
      } ].concat(VALUE)
    };
    /* Rule-Level Modes */    var RULE_MODE = {
      begin: INTERP_IDENT_RE + "\\s*:",
      returnBegin: true,
      end: "[;}]",
      relevance: 0,
      contains: [ {
        className: "attribute",
        begin: INTERP_IDENT_RE,
        end: ":",
        excludeEnd: true,
        starts: {
          endsWithParent: true,
          illegal: "[<=$]",
          relevance: 0,
          contains: VALUE
        }
      } ]
    };
    var AT_RULE_MODE = {
      className: "keyword",
      begin: "@(import|media|charset|font-face|(-[a-z]+-)?keyframes|supports|document|namespace|page|viewport|host)\\b",
      starts: {
        end: "[;{}]",
        returnEnd: true,
        contains: VALUE,
        relevance: 0
      }
    };
    // variable definitions and calls
        var VAR_RULE_MODE = {
      className: "variable",
      variants: [ 
      // using more strict pattern for higher relevance to increase chances of Less detection.
      // this is *the only* Less specific statement used in most of the sources, so...
      // (we’ll still often loose to the css-parser unless there's '//' comment,
      // simply because 1 variable just can't beat 99 properties :)
      {
        begin: "@" + IDENT_RE + "\\s*:",
        relevance: 15
      }, {
        begin: "@" + IDENT_RE
      } ],
      starts: {
        end: "[;}]",
        returnEnd: true,
        contains: VALUE_WITH_RULESETS
      }
    };
    var SELECTOR_MODE = {
      // first parse unambiguous selectors (i.e. those not starting with tag)
      // then fall into the scary lookahead-discriminator variant.
      // this mode also handles mixin definitions and calls
      variants: [ {
        begin: "[\\.#:&\\[>]",
        end: "[;{}]"
      }, {
        begin: INTERP_IDENT_RE,
        end: /\{/
      } ],
      returnBegin: true,
      returnEnd: true,
      illegal: "[<='$\"]",
      relevance: 0,
      contains: [ hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, MIXIN_GUARD_MODE, IDENT_MODE("keyword", "all\\b"), IDENT_MODE("variable", "@\\{" + IDENT_RE + "\\}"), // otherwise it’s identified as tag
      IDENT_MODE("selector-tag", INTERP_IDENT_RE + "%?", 0), // '%' for more consistent coloring of @keyframes "tags"
      IDENT_MODE("selector-id", "#" + INTERP_IDENT_RE), IDENT_MODE("selector-class", "\\." + INTERP_IDENT_RE, 0), IDENT_MODE("selector-tag", "&", 0), {
        className: "selector-attr",
        begin: "\\[",
        end: "\\]"
      }, {
        className: "selector-pseudo",
        begin: /:(:)?[a-zA-Z0-9_\-+()"'.]+/
      }, {
        begin: "\\(",
        end: "\\)",
        contains: VALUE_WITH_RULESETS
      }, // argument list of parametric mixins
      {
        begin: "!important"
      } ]
    };
    RULES.push(hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, AT_RULE_MODE, VAR_RULE_MODE, RULE_MODE, SELECTOR_MODE);
    return {
      name: "Less",
      case_insensitive: true,
      illegal: "[=>'/<($\"]",
      contains: RULES
    };
  }
  var less_1 = less;
  /*
  Language: Lisp
  Description: Generic lisp syntax
  Author: Vasily Polovnyov <vast@whiteants.net>
  Category: lisp
  */  function lisp(hljs) {
    var LISP_IDENT_RE = "[a-zA-Z_\\-+\\*\\/<=>&#][a-zA-Z0-9_\\-+*\\/<=>&#!]*";
    var MEC_RE = "\\|[^]*?\\|";
    var LISP_SIMPLE_NUMBER_RE = "(-|\\+)?\\d+(\\.\\d+|\\/\\d+)?((d|e|f|l|s|D|E|F|L|S)(\\+|-)?\\d+)?";
    var LITERAL = {
      className: "literal",
      begin: "\\b(t{1}|nil)\\b"
    };
    var NUMBER = {
      className: "number",
      variants: [ {
        begin: LISP_SIMPLE_NUMBER_RE,
        relevance: 0
      }, {
        begin: "#(b|B)[0-1]+(/[0-1]+)?"
      }, {
        begin: "#(o|O)[0-7]+(/[0-7]+)?"
      }, {
        begin: "#(x|X)[0-9a-fA-F]+(/[0-9a-fA-F]+)?"
      }, {
        begin: "#(c|C)\\(" + LISP_SIMPLE_NUMBER_RE + " +" + LISP_SIMPLE_NUMBER_RE,
        end: "\\)"
      } ]
    };
    var STRING = hljs.inherit(hljs.QUOTE_STRING_MODE, {
      illegal: null
    });
    var COMMENT = hljs.COMMENT(";", "$", {
      relevance: 0
    });
    var VARIABLE = {
      begin: "\\*",
      end: "\\*"
    };
    var KEYWORD = {
      className: "symbol",
      begin: "[:&]" + LISP_IDENT_RE
    };
    var IDENT = {
      begin: LISP_IDENT_RE,
      relevance: 0
    };
    var MEC = {
      begin: MEC_RE
    };
    var QUOTED_LIST = {
      begin: "\\(",
      end: "\\)",
      contains: [ "self", LITERAL, STRING, NUMBER, IDENT ]
    };
    var QUOTED = {
      contains: [ NUMBER, STRING, VARIABLE, KEYWORD, QUOTED_LIST, IDENT ],
      variants: [ {
        begin: "['`]\\(",
        end: "\\)"
      }, {
        begin: "\\(quote ",
        end: "\\)",
        keywords: {
          name: "quote"
        }
      }, {
        begin: "'" + MEC_RE
      } ]
    };
    var QUOTED_ATOM = {
      variants: [ {
        begin: "'" + LISP_IDENT_RE
      }, {
        begin: "#'" + LISP_IDENT_RE + "(::" + LISP_IDENT_RE + ")*"
      } ]
    };
    var LIST = {
      begin: "\\(\\s*",
      end: "\\)"
    };
    var BODY = {
      endsWithParent: true,
      relevance: 0
    };
    LIST.contains = [ {
      className: "name",
      variants: [ {
        begin: LISP_IDENT_RE,
        relevance: 0
      }, {
        begin: MEC_RE
      } ]
    }, BODY ];
    BODY.contains = [ QUOTED, QUOTED_ATOM, LIST, LITERAL, NUMBER, STRING, COMMENT, VARIABLE, KEYWORD, MEC, IDENT ];
    return {
      name: "Lisp",
      illegal: /\S/,
      contains: [ NUMBER, hljs.SHEBANG(), LITERAL, STRING, COMMENT, QUOTED, QUOTED_ATOM, LIST, IDENT ]
    };
  }
  var lisp_1 = lisp;
  const KEYWORDS$2 = [ "as", // for exports
  "in", "of", "if", "for", "while", "finally", "var", "new", "function", "do", "return", "void", "else", "break", "catch", "instanceof", "with", "throw", "case", "default", "try", "switch", "continue", "typeof", "delete", "let", "yield", "const", "class", 
  // JS handles these with a special rule
  // "get",
  // "set",
  "debugger", "async", "await", "static", "import", "from", "export", "extends" ];
  const LITERALS$2 = [ "true", "false", "null", "undefined", "NaN", "Infinity" ];
  const TYPES$2 = [ "Intl", "DataView", "Number", "Math", "Date", "String", "RegExp", "Object", "Function", "Boolean", "Error", "Symbol", "Set", "Map", "WeakSet", "WeakMap", "Proxy", "Reflect", "JSON", "Promise", "Float64Array", "Int16Array", "Int32Array", "Int8Array", "Uint16Array", "Uint32Array", "Float32Array", "Array", "Uint8Array", "Uint8ClampedArray", "ArrayBuffer" ];
  const ERROR_TYPES$2 = [ "EvalError", "InternalError", "RangeError", "ReferenceError", "SyntaxError", "TypeError", "URIError" ];
  const BUILT_IN_GLOBALS$2 = [ "setInterval", "setTimeout", "clearInterval", "clearTimeout", "require", "exports", "eval", "isFinite", "isNaN", "parseFloat", "parseInt", "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent", "escape", "unescape" ];
  const BUILT_IN_VARIABLES$2 = [ "arguments", "this", "super", "console", "window", "document", "localStorage", "module", "global" ];
  const BUILT_INS$2 = [].concat(BUILT_IN_GLOBALS$2, BUILT_IN_VARIABLES$2, TYPES$2, ERROR_TYPES$2);
  /*
  Language: LiveScript
  Author: Taneli Vatanen <taneli.vatanen@gmail.com>
  Contributors: Jen Evers-Corvina <jen@sevvie.net>
  Origin: coffeescript.js
  Description: LiveScript is a programming language that transcompiles to JavaScript. For info about language see http://livescript.net/
  Website: https://livescript.net
  Category: scripting
  */  function livescript(hljs) {
    const LIVESCRIPT_BUILT_INS = [ "npm", "print" ];
    const LIVESCRIPT_LITERALS = [ "yes", "no", "on", "off", "it", "that", "void" ];
    const LIVESCRIPT_KEYWORDS = [ "then", "unless", "until", "loop", "of", "by", "when", "and", "or", "is", "isnt", "not", "it", "that", "otherwise", "from", "to", "til", "fallthrough", "case", "enum", "native", "list", "map", "__hasProp", "__extends", "__slice", "__bind", "__indexOf" ];
    const KEYWORDS$1 = {
      keyword: KEYWORDS$2.concat(LIVESCRIPT_KEYWORDS).join(" "),
      literal: LITERALS$2.concat(LIVESCRIPT_LITERALS).join(" "),
      built_in: BUILT_INS$2.concat(LIVESCRIPT_BUILT_INS).join(" ")
    };
    const JS_IDENT_RE = "[A-Za-z$_](?:-[0-9A-Za-z$_]|[0-9A-Za-z$_])*";
    const TITLE = hljs.inherit(hljs.TITLE_MODE, {
      begin: JS_IDENT_RE
    });
    const SUBST = {
      className: "subst",
      begin: /#\{/,
      end: /\}/,
      keywords: KEYWORDS$1
    };
    const SUBST_SIMPLE = {
      className: "subst",
      begin: /#[A-Za-z$_]/,
      end: /(?:-[0-9A-Za-z$_]|[0-9A-Za-z$_])*/,
      keywords: KEYWORDS$1
    };
    const EXPRESSIONS = [ hljs.BINARY_NUMBER_MODE, {
      className: "number",
      begin: "(\\b0[xX][a-fA-F0-9_]+)|(\\b\\d(\\d|_\\d)*(\\.(\\d(\\d|_\\d)*)?)?(_*[eE]([-+]\\d(_\\d|\\d)*)?)?[_a-z]*)",
      relevance: 0,
      starts: {
        end: "(\\s*/)?",
        relevance: 0
      }
    }, {
      className: "string",
      variants: [ {
        begin: /'''/,
        end: /'''/,
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: /'/,
        end: /'/,
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: /"""/,
        end: /"""/,
        contains: [ hljs.BACKSLASH_ESCAPE, SUBST, SUBST_SIMPLE ]
      }, {
        begin: /"/,
        end: /"/,
        contains: [ hljs.BACKSLASH_ESCAPE, SUBST, SUBST_SIMPLE ]
      }, {
        begin: /\\/,
        end: /(\s|$)/,
        excludeEnd: true
      } ]
    }, {
      className: "regexp",
      variants: [ {
        begin: "//",
        end: "//[gim]*",
        contains: [ SUBST, hljs.HASH_COMMENT_MODE ]
      }, {
        // regex can't start with space to parse x / 2 / 3 as two divisions
        // regex can't start with *, and it supports an "illegal" in the main mode
        begin: /\/(?![ *])(\\.|[^\\\n])*?\/[gim]*(?=\W)/
      } ]
    }, {
      begin: "@" + JS_IDENT_RE
    }, {
      begin: "``",
      end: "``",
      excludeBegin: true,
      excludeEnd: true,
      subLanguage: "javascript"
    } ];
    SUBST.contains = EXPRESSIONS;
    const PARAMS = {
      className: "params",
      begin: "\\(",
      returnBegin: true,
      /* We need another contained nameless mode to not have every nested
      pair of parens to be called "params" */
      contains: [ {
        begin: /\(/,
        end: /\)/,
        keywords: KEYWORDS$1,
        contains: [ "self" ].concat(EXPRESSIONS)
      } ]
    };
    const SYMBOLS = {
      begin: "(#=>|=>|\\|>>|-?->|!->)"
    };
    return {
      name: "LiveScript",
      aliases: [ "ls" ],
      keywords: KEYWORDS$1,
      illegal: /\/\*/,
      contains: EXPRESSIONS.concat([ hljs.COMMENT("\\/\\*", "\\*\\/"), hljs.HASH_COMMENT_MODE, SYMBOLS, // relevance booster
      {
        className: "function",
        contains: [ TITLE, PARAMS ],
        returnBegin: true,
        variants: [ {
          begin: "(" + JS_IDENT_RE + "\\s*(?:=|:=)\\s*)?(\\(.*\\)\\s*)?\\B->\\*?",
          end: "->\\*?"
        }, {
          begin: "(" + JS_IDENT_RE + "\\s*(?:=|:=)\\s*)?!?(\\(.*\\)\\s*)?\\B[-~]{1,2}>\\*?",
          end: "[-~]{1,2}>\\*?"
        }, {
          begin: "(" + JS_IDENT_RE + "\\s*(?:=|:=)\\s*)?(\\(.*\\)\\s*)?\\B!?[-~]{1,2}>\\*?",
          end: "!?[-~]{1,2}>\\*?"
        } ]
      }, {
        className: "class",
        beginKeywords: "class",
        end: "$",
        illegal: /[:="\[\]]/,
        contains: [ {
          beginKeywords: "extends",
          endsWithParent: true,
          illegal: /[:="\[\]]/,
          contains: [ TITLE ]
        }, TITLE ]
      }, {
        begin: JS_IDENT_RE + ":",
        end: ":",
        returnBegin: true,
        returnEnd: true,
        relevance: 0
      } ])
    };
  }
  var livescript_1 = livescript;
  /*
  Language: Lua
  Description: Lua is a powerful, efficient, lightweight, embeddable scripting language.
  Author: Andrew Fedorov <dmmdrs@mail.ru>
  Category: common, scripting
  Website: https://www.lua.org
  */  function lua(hljs) {
    const OPENING_LONG_BRACKET = "\\[=*\\[";
    const CLOSING_LONG_BRACKET = "\\]=*\\]";
    const LONG_BRACKETS = {
      begin: OPENING_LONG_BRACKET,
      end: CLOSING_LONG_BRACKET,
      contains: [ "self" ]
    };
    const COMMENTS = [ hljs.COMMENT("--(?!" + OPENING_LONG_BRACKET + ")", "$"), hljs.COMMENT("--" + OPENING_LONG_BRACKET, CLOSING_LONG_BRACKET, {
      contains: [ LONG_BRACKETS ],
      relevance: 10
    }) ];
    return {
      name: "Lua",
      keywords: {
        $pattern: hljs.UNDERSCORE_IDENT_RE,
        literal: "true false nil",
        keyword: "and break do else elseif end for goto if in local not or repeat return then until while",
        built_in: 
        // Metatags and globals:
        "_G _ENV _VERSION __index __newindex __mode __call __metatable __tostring __len " + "__gc __add __sub __mul __div __mod __pow __concat __unm __eq __lt __le assert " + 
        // Standard methods and properties:
        "collectgarbage dofile error getfenv getmetatable ipairs load loadfile loadstring " + "module next pairs pcall print rawequal rawget rawset require select setfenv " + "setmetatable tonumber tostring type unpack xpcall arg self " + 
        // Library methods and properties (one line per library):
        "coroutine resume yield status wrap create running debug getupvalue " + "debug sethook getmetatable gethook setmetatable setlocal traceback setfenv getinfo setupvalue getlocal getregistry getfenv " + "io lines write close flush open output type read stderr stdin input stdout popen tmpfile " + "math log max acos huge ldexp pi cos tanh pow deg tan cosh sinh random randomseed frexp ceil floor rad abs sqrt modf asin min mod fmod log10 atan2 exp sin atan " + "os exit setlocale date getenv difftime remove time clock tmpname rename execute package preload loadlib loaded loaders cpath config path seeall " + "string sub upper len gfind rep find match char dump gmatch reverse byte format gsub lower " + "table setn insert getn foreachi maxn foreach concat sort remove"
      },
      contains: COMMENTS.concat([ {
        className: "function",
        beginKeywords: "function",
        end: "\\)",
        contains: [ hljs.inherit(hljs.TITLE_MODE, {
          begin: "([_a-zA-Z]\\w*\\.)*([_a-zA-Z]\\w*:)?[_a-zA-Z]\\w*"
        }), {
          className: "params",
          begin: "\\(",
          endsWithParent: true,
          contains: COMMENTS
        } ].concat(COMMENTS)
      }, hljs.C_NUMBER_MODE, hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, {
        className: "string",
        begin: OPENING_LONG_BRACKET,
        end: CLOSING_LONG_BRACKET,
        contains: [ LONG_BRACKETS ],
        relevance: 5
      } ])
    };
  }
  var lua_1 = lua;
  /*
  Language: Makefile
  Author: Ivan Sagalaev <maniac@softwaremaniacs.org>
  Contributors: Joël Porquet <joel@porquet.org>
  Website: https://www.gnu.org/software/make/manual/html_node/Introduction.html
  Category: common
  */  function makefile(hljs) {
    /* Variables: simple (eg $(var)) and special (eg $@) */
    const VARIABLE = {
      className: "variable",
      variants: [ {
        begin: "\\$\\(" + hljs.UNDERSCORE_IDENT_RE + "\\)",
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: /\$[@%<?\^\+\*]/
      } ]
    };
    /* Quoted string with variables inside */    const QUOTE_STRING = {
      className: "string",
      begin: /"/,
      end: /"/,
      contains: [ hljs.BACKSLASH_ESCAPE, VARIABLE ]
    };
    /* Function: $(func arg,...) */    const FUNC = {
      className: "variable",
      begin: /\$\([\w-]+\s/,
      end: /\)/,
      keywords: {
        built_in: "subst patsubst strip findstring filter filter-out sort " + "word wordlist firstword lastword dir notdir suffix basename " + "addsuffix addprefix join wildcard realpath abspath error warning " + "shell origin flavor foreach if or and call eval file value"
      },
      contains: [ VARIABLE ]
    };
    /* Variable assignment */    const ASSIGNMENT = {
      begin: "^" + hljs.UNDERSCORE_IDENT_RE + "\\s*(?=[:+?]?=)"
    };
    /* Meta targets (.PHONY) */    const META = {
      className: "meta",
      begin: /^\.PHONY:/,
      end: /$/,
      keywords: {
        $pattern: /[\.\w]+/,
        "meta-keyword": ".PHONY"
      }
    };
    /* Targets */    const TARGET = {
      className: "section",
      begin: /^[^\s]+:/,
      end: /$/,
      contains: [ VARIABLE ]
    };
    return {
      name: "Makefile",
      aliases: [ "mk", "mak" ],
      keywords: {
        $pattern: /[\w-]+/,
        keyword: "define endef undefine ifdef ifndef ifeq ifneq else endif " + "include -include sinclude override export unexport private vpath"
      },
      contains: [ hljs.HASH_COMMENT_MODE, VARIABLE, QUOTE_STRING, FUNC, ASSIGNMENT, META, TARGET ]
    };
  }
  var makefile_1 = makefile;
  /*
  Language: Matlab
  Author: Denis Bardadym <bardadymchik@gmail.com>
  Contributors: Eugene Nizhibitsky <nizhibitsky@ya.ru>, Egor Rogov <e.rogov@postgrespro.ru>
  Website: https://www.mathworks.com/products/matlab.html
  Category: scientific
  */
  /*
    Formal syntax is not published, helpful link:
    https://github.com/kornilova-l/matlab-IntelliJ-plugin/blob/master/src/main/grammar/Matlab.bnf
  */  function matlab(hljs) {
    var TRANSPOSE_RE = "('|\\.')+";
    var TRANSPOSE = {
      relevance: 0,
      contains: [ {
        begin: TRANSPOSE_RE
      } ]
    };
    return {
      name: "Matlab",
      keywords: {
        keyword: "arguments break case catch classdef continue else elseif end enumeration events for function " + "global if methods otherwise parfor persistent properties return spmd switch try while",
        built_in: "sin sind sinh asin asind asinh cos cosd cosh acos acosd acosh tan tand tanh atan " + "atand atan2 atanh sec secd sech asec asecd asech csc cscd csch acsc acscd acsch cot " + "cotd coth acot acotd acoth hypot exp expm1 log log1p log10 log2 pow2 realpow reallog " + "realsqrt sqrt nthroot nextpow2 abs angle complex conj imag real unwrap isreal " + "cplxpair fix floor ceil round mod rem sign airy besselj bessely besselh besseli " + "besselk beta betainc betaln ellipj ellipke erf erfc erfcx erfinv expint gamma " + "gammainc gammaln psi legendre cross dot factor isprime primes gcd lcm rat rats perms " + "nchoosek factorial cart2sph cart2pol pol2cart sph2cart hsv2rgb rgb2hsv zeros ones " + "eye repmat rand randn linspace logspace freqspace meshgrid accumarray size length " + "ndims numel disp isempty isequal isequalwithequalnans cat reshape diag blkdiag tril " + "triu fliplr flipud flipdim rot90 find sub2ind ind2sub bsxfun ndgrid permute ipermute " + "shiftdim circshift squeeze isscalar isvector ans eps realmax realmin pi i|0 inf nan " + "isnan isinf isfinite j|0 why compan gallery hadamard hankel hilb invhilb magic pascal " + "rosser toeplitz vander wilkinson max min nanmax nanmin mean nanmean type table " + "readtable writetable sortrows sort figure plot plot3 scatter scatter3 cellfun " + "legend intersect ismember procrustes hold num2cell "
      },
      illegal: '(//|"|#|/\\*|\\s+/\\w+)',
      contains: [ {
        className: "function",
        beginKeywords: "function",
        end: "$",
        contains: [ hljs.UNDERSCORE_TITLE_MODE, {
          className: "params",
          variants: [ {
            begin: "\\(",
            end: "\\)"
          }, {
            begin: "\\[",
            end: "\\]"
          } ]
        } ]
      }, {
        className: "built_in",
        begin: /true|false/,
        relevance: 0,
        starts: TRANSPOSE
      }, {
        begin: "[a-zA-Z][a-zA-Z_0-9]*" + TRANSPOSE_RE,
        relevance: 0
      }, {
        className: "number",
        begin: hljs.C_NUMBER_RE,
        relevance: 0,
        starts: TRANSPOSE
      }, {
        className: "string",
        begin: "'",
        end: "'",
        contains: [ hljs.BACKSLASH_ESCAPE, {
          begin: "''"
        } ]
      }, {
        begin: /\]|\}|\)/,
        relevance: 0,
        starts: TRANSPOSE
      }, {
        className: "string",
        begin: '"',
        end: '"',
        contains: [ hljs.BACKSLASH_ESCAPE, {
          begin: '""'
        } ],
        starts: TRANSPOSE
      }, hljs.COMMENT("^\\s*%\\{\\s*$", "^\\s*%\\}\\s*$"), hljs.COMMENT("%", "$") ]
    };
  }
  var matlab_1 = matlab;
  /*
  Language: MIPS Assembly
  Author: Nebuleon Fumika <nebuleon.fumika@gmail.com>
  Description: MIPS Assembly (up to MIPS32R2)
  Website: https://en.wikipedia.org/wiki/MIPS_architecture
  Category: assembler
  */  function mipsasm(hljs) {
    // local labels: %?[FB]?[AT]?\d{1,2}\w+
    return {
      name: "MIPS Assembly",
      case_insensitive: true,
      aliases: [ "mips" ],
      keywords: {
        $pattern: "\\.?" + hljs.IDENT_RE,
        meta: 
        // GNU preprocs
        ".2byte .4byte .align .ascii .asciz .balign .byte .code .data .else .end .endif .endm .endr .equ .err .exitm .extern .global .hword .if .ifdef .ifndef .include .irp .long .macro .rept .req .section .set .skip .space .text .word .ltorg ",
        built_in: "$0 $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 " + // integer registers
        "$16 $17 $18 $19 $20 $21 $22 $23 $24 $25 $26 $27 $28 $29 $30 $31 " + // integer registers
        "zero at v0 v1 a0 a1 a2 a3 a4 a5 a6 a7 " + // integer register aliases
        "t0 t1 t2 t3 t4 t5 t6 t7 t8 t9 s0 s1 s2 s3 s4 s5 s6 s7 s8 " + // integer register aliases
        "k0 k1 gp sp fp ra " + // integer register aliases
        "$f0 $f1 $f2 $f2 $f4 $f5 $f6 $f7 $f8 $f9 $f10 $f11 $f12 $f13 $f14 $f15 " + // floating-point registers
        "$f16 $f17 $f18 $f19 $f20 $f21 $f22 $f23 $f24 $f25 $f26 $f27 $f28 $f29 $f30 $f31 " + // floating-point registers
        "Context Random EntryLo0 EntryLo1 Context PageMask Wired EntryHi " + // Coprocessor 0 registers
        "HWREna BadVAddr Count Compare SR IntCtl SRSCtl SRSMap Cause EPC PRId " + // Coprocessor 0 registers
        "EBase Config Config1 Config2 Config3 LLAddr Debug DEPC DESAVE CacheErr " + // Coprocessor 0 registers
        "ECC ErrorEPC TagLo DataLo TagHi DataHi WatchLo WatchHi PerfCtl PerfCnt "
      },
      contains: [ {
        className: "keyword",
        begin: "\\b(" + // mnemonics
        // 32-bit integer instructions
        "addi?u?|andi?|b(al)?|beql?|bgez(al)?l?|bgtzl?|blezl?|bltz(al)?l?|" + "bnel?|cl[oz]|divu?|ext|ins|j(al)?|jalr(\\.hb)?|jr(\\.hb)?|lbu?|lhu?|" + "ll|lui|lw[lr]?|maddu?|mfhi|mflo|movn|movz|move|msubu?|mthi|mtlo|mul|" + "multu?|nop|nor|ori?|rotrv?|sb|sc|se[bh]|sh|sllv?|slti?u?|srav?|" + "srlv?|subu?|sw[lr]?|xori?|wsbh|" + 
        // floating-point instructions
        "abs\\.[sd]|add\\.[sd]|alnv.ps|bc1[ft]l?|" + "c\\.(s?f|un|u?eq|[ou]lt|[ou]le|ngle?|seq|l[et]|ng[et])\\.[sd]|" + "(ceil|floor|round|trunc)\\.[lw]\\.[sd]|cfc1|cvt\\.d\\.[lsw]|" + "cvt\\.l\\.[dsw]|cvt\\.ps\\.s|cvt\\.s\\.[dlw]|cvt\\.s\\.p[lu]|cvt\\.w\\.[dls]|" + "div\\.[ds]|ldx?c1|luxc1|lwx?c1|madd\\.[sd]|mfc1|mov[fntz]?\\.[ds]|" + "msub\\.[sd]|mth?c1|mul\\.[ds]|neg\\.[ds]|nmadd\\.[ds]|nmsub\\.[ds]|" + "p[lu][lu]\\.ps|recip\\.fmt|r?sqrt\\.[ds]|sdx?c1|sub\\.[ds]|suxc1|" + "swx?c1|" + 
        // system control instructions
        "break|cache|d?eret|[de]i|ehb|mfc0|mtc0|pause|prefx?|rdhwr|" + "rdpgpr|sdbbp|ssnop|synci?|syscall|teqi?|tgei?u?|tlb(p|r|w[ir])|" + "tlti?u?|tnei?|wait|wrpgpr" + ")",
        end: "\\s"
      }, 
      // lines ending with ; or # aren't really comments, probably auto-detect fail
      hljs.COMMENT("[;#](?!\\s*$)", "$"), hljs.C_BLOCK_COMMENT_MODE, hljs.QUOTE_STRING_MODE, {
        className: "string",
        begin: "'",
        end: "[^\\\\]'",
        relevance: 0
      }, {
        className: "title",
        begin: "\\|",
        end: "\\|",
        illegal: "\\n",
        relevance: 0
      }, {
        className: "number",
        variants: [ {
          // hex
          begin: "0x[0-9a-f]+"
        }, {
          // bare number
          begin: "\\b-?\\d+"
        } ],
        relevance: 0
      }, {
        className: "symbol",
        variants: [ {
          // GNU MIPS syntax
          begin: "^\\s*[a-z_\\.\\$][a-z0-9_\\.\\$]+:"
        }, {
          // numbered local labels
          begin: "^\\s*[0-9]+:"
        }, {
          // number local label reference (backwards, forwards)
          begin: "[0-9]+[bf]"
        } ],
        relevance: 0
      } ],
      // forward slashes are not allowed
      illegal: /\//
    };
  }
  var mipsasm_1 = mipsasm;
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$e(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$d(...args) {
    const joined = args.map((x => source$e(x))).join("");
    return joined;
  }
  /*
  Language: Perl
  Author: Peter Leonov <gojpeg@yandex.ru>
  Website: https://www.perl.org
  Category: common
  */
  /** @type LanguageFn */  function perl(hljs) {
    // https://perldoc.perl.org/perlre#Modifiers
    const REGEX_MODIFIERS = /[dualxmsipn]{0,12}/;
 // aa and xx are valid, making max length 12
        const PERL_KEYWORDS = {
      $pattern: /[\w.]+/,
      keyword: "getpwent getservent quotemeta msgrcv scalar kill dbmclose undef lc " + "ma syswrite tr send umask sysopen shmwrite vec qx utime local oct semctl localtime " + "readpipe do return format read sprintf dbmopen pop getpgrp not getpwnam rewinddir qq " + "fileno qw endprotoent wait sethostent bless s|0 opendir continue each sleep endgrent " + "shutdown dump chomp connect getsockname die socketpair close flock exists index shmget " + "sub for endpwent redo lstat msgctl setpgrp abs exit select print ref gethostbyaddr " + "unshift fcntl syscall goto getnetbyaddr join gmtime symlink semget splice x|0 " + "getpeername recv log setsockopt cos last reverse gethostbyname getgrnam study formline " + "endhostent times chop length gethostent getnetent pack getprotoent getservbyname rand " + "mkdir pos chmod y|0 substr endnetent printf next open msgsnd readdir use unlink " + "getsockopt getpriority rindex wantarray hex system getservbyport endservent int chr " + "untie rmdir prototype tell listen fork shmread ucfirst setprotoent else sysseek link " + "getgrgid shmctl waitpid unpack getnetbyname reset chdir grep split require caller " + "lcfirst until warn while values shift telldir getpwuid my getprotobynumber delete and " + "sort uc defined srand accept package seekdir getprotobyname semop our rename seek if q|0 " + "chroot sysread setpwent no crypt getc chown sqrt write setnetent setpriority foreach " + "tie sin msgget map stat getlogin unless elsif truncate exec keys glob tied closedir " + "ioctl socket readlink eval xor readline binmode setservent eof ord bind alarm pipe " + "atan2 getgrent exp time push setgrent gt lt or ne m|0 break given say state when"
    };
    const SUBST = {
      className: "subst",
      begin: "[$@]\\{",
      end: "\\}",
      keywords: PERL_KEYWORDS
    };
    const METHOD = {
      begin: /->\{/,
      end: /\}/
    };
    const VAR = {
      variants: [ {
        begin: /\$\d/
      }, {
        begin: concat$d(/[$%@](\^\w\b|#\w+(::\w+)*|\{\w+\}|\w+(::\w*)*)/, 
        // negative look-ahead tries to avoid matching patterns that are not
        // Perl at all like $ident$, @ident@, etc.
        `(?![A-Za-z])(?![@$%])`)
      }, {
        begin: /[$%@][^\s\w{]/,
        relevance: 0
      } ]
    };
    const STRING_CONTAINS = [ hljs.BACKSLASH_ESCAPE, SUBST, VAR ];
    const PERL_DEFAULT_CONTAINS = [ VAR, hljs.HASH_COMMENT_MODE, hljs.COMMENT(/^=\w/, /=cut/, {
      endsWithParent: true
    }), METHOD, {
      className: "string",
      contains: STRING_CONTAINS,
      variants: [ {
        begin: "q[qwxr]?\\s*\\(",
        end: "\\)",
        relevance: 5
      }, {
        begin: "q[qwxr]?\\s*\\[",
        end: "\\]",
        relevance: 5
      }, {
        begin: "q[qwxr]?\\s*\\{",
        end: "\\}",
        relevance: 5
      }, {
        begin: "q[qwxr]?\\s*\\|",
        end: "\\|",
        relevance: 5
      }, {
        begin: "q[qwxr]?\\s*<",
        end: ">",
        relevance: 5
      }, {
        begin: "qw\\s+q",
        end: "q",
        relevance: 5
      }, {
        begin: "'",
        end: "'",
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: '"',
        end: '"'
      }, {
        begin: "`",
        end: "`",
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: /\{\w+\}/,
        contains: [],
        relevance: 0
      }, {
        begin: "-?\\w+\\s*=>",
        contains: [],
        relevance: 0
      } ]
    }, {
      className: "number",
      begin: "(\\b0[0-7_]+)|(\\b0x[0-9a-fA-F_]+)|(\\b[1-9][0-9_]*(\\.[0-9_]+)?)|[0_]\\b",
      relevance: 0
    }, {
      // regexp container
      begin: "(\\/\\/|" + hljs.RE_STARTERS_RE + "|\\b(split|return|print|reverse|grep)\\b)\\s*",
      keywords: "split return print reverse grep",
      relevance: 0,
      contains: [ hljs.HASH_COMMENT_MODE, {
        className: "regexp",
        begin: concat$d(/(s|tr|y)/, /\//, /(\\.|[^\\\/])*/, /\//, /(\\.|[^\\\/])*/, /\//, REGEX_MODIFIERS),
        relevance: 10
      }, {
        className: "regexp",
        begin: /(m|qr)?\//,
        end: concat$d(/\//, REGEX_MODIFIERS),
        contains: [ hljs.BACKSLASH_ESCAPE ],
        relevance: 0
      } ]
    }, {
      className: "function",
      beginKeywords: "sub",
      end: "(\\s*\\(.*?\\))?[;{]",
      excludeEnd: true,
      relevance: 5,
      contains: [ hljs.TITLE_MODE ]
    }, {
      begin: "-\\w\\b",
      relevance: 0
    }, {
      begin: "^__DATA__$",
      end: "^__END__$",
      subLanguage: "mojolicious",
      contains: [ {
        begin: "^@@.*",
        end: "$",
        className: "comment"
      } ]
    } ];
    SUBST.contains = PERL_DEFAULT_CONTAINS;
    METHOD.contains = PERL_DEFAULT_CONTAINS;
    return {
      name: "Perl",
      aliases: [ "pl", "pm" ],
      keywords: PERL_KEYWORDS,
      contains: PERL_DEFAULT_CONTAINS
    };
  }
  var perl_1 = perl;
  /*
  Language: Nginx config
  Author: Peter Leonov <gojpeg@yandex.ru>
  Contributors: Ivan Sagalaev <maniac@softwaremaniacs.org>
  Category: common, config
  Website: https://www.nginx.com
  */  function nginx(hljs) {
    const VAR = {
      className: "variable",
      variants: [ {
        begin: /\$\d+/
      }, {
        begin: /\$\{/,
        end: /\}/
      }, {
        begin: /[$@]/ + hljs.UNDERSCORE_IDENT_RE
      } ]
    };
    const DEFAULT = {
      endsWithParent: true,
      keywords: {
        $pattern: "[a-z/_]+",
        literal: "on off yes no true false none blocked debug info notice warn error crit " + "select break last permanent redirect kqueue rtsig epoll poll /dev/poll"
      },
      relevance: 0,
      illegal: "=>",
      contains: [ hljs.HASH_COMMENT_MODE, {
        className: "string",
        contains: [ hljs.BACKSLASH_ESCAPE, VAR ],
        variants: [ {
          begin: /"/,
          end: /"/
        }, {
          begin: /'/,
          end: /'/
        } ]
      }, 
      // this swallows entire URLs to avoid detecting numbers within
      {
        begin: "([a-z]+):/",
        end: "\\s",
        endsWithParent: true,
        excludeEnd: true,
        contains: [ VAR ]
      }, {
        className: "regexp",
        contains: [ hljs.BACKSLASH_ESCAPE, VAR ],
        variants: [ {
          begin: "\\s\\^",
          end: "\\s|\\{|;",
          returnEnd: true
        }, 
        // regexp locations (~, ~*)
        {
          begin: "~\\*?\\s+",
          end: "\\s|\\{|;",
          returnEnd: true
        }, 
        // *.example.com
        {
          begin: "\\*(\\.[a-z\\-]+)+"
        }, 
        // sub.example.*
        {
          begin: "([a-z\\-]+\\.)+\\*"
        } ]
      }, 
      // IP
      {
        className: "number",
        begin: "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d{1,5})?\\b"
      }, 
      // units
      {
        className: "number",
        begin: "\\b\\d+[kKmMgGdshdwy]*\\b",
        relevance: 0
      }, VAR ]
    };
    return {
      name: "Nginx config",
      aliases: [ "nginxconf" ],
      contains: [ hljs.HASH_COMMENT_MODE, {
        begin: hljs.UNDERSCORE_IDENT_RE + "\\s+\\{",
        returnBegin: true,
        end: /\{/,
        contains: [ {
          className: "section",
          begin: hljs.UNDERSCORE_IDENT_RE
        } ],
        relevance: 0
      }, {
        begin: hljs.UNDERSCORE_IDENT_RE + "\\s",
        end: ";|\\{",
        returnBegin: true,
        contains: [ {
          className: "attribute",
          begin: hljs.UNDERSCORE_IDENT_RE,
          starts: DEFAULT
        } ],
        relevance: 0
      } ],
      illegal: "[^\\s\\}]"
    };
  }
  var nginx_1 = nginx;
  /*
  Language: Objective-C
  Author: Valerii Hiora <valerii.hiora@gmail.com>
  Contributors: Angel G. Olloqui <angelgarcia.mail@gmail.com>, Matt Diephouse <matt@diephouse.com>, Andrew Farmer <ahfarmer@gmail.com>, Minh Nguyễn <mxn@1ec5.org>
  Website: https://developer.apple.com/documentation/objectivec
  Category: common
  */  function objectivec(hljs) {
    const API_CLASS = {
      className: "built_in",
      begin: "\\b(AV|CA|CF|CG|CI|CL|CM|CN|CT|MK|MP|MTK|MTL|NS|SCN|SK|UI|WK|XC)\\w+"
    };
    const IDENTIFIER_RE = /[a-zA-Z@][a-zA-Z0-9_]*/;
    const OBJC_KEYWORDS = {
      $pattern: IDENTIFIER_RE,
      keyword: "int float while char export sizeof typedef const struct for union " + "unsigned long volatile static bool mutable if do return goto void " + "enum else break extern asm case short default double register explicit " + "signed typename this switch continue wchar_t inline readonly assign " + "readwrite self @synchronized id typeof " + "nonatomic super unichar IBOutlet IBAction strong weak copy " + "in out inout bycopy byref oneway __strong __weak __block __autoreleasing " + "@private @protected @public @try @property @end @throw @catch @finally " + "@autoreleasepool @synthesize @dynamic @selector @optional @required " + "@encode @package @import @defs @compatibility_alias " + "__bridge __bridge_transfer __bridge_retained __bridge_retain " + "__covariant __contravariant __kindof " + "_Nonnull _Nullable _Null_unspecified " + "__FUNCTION__ __PRETTY_FUNCTION__ __attribute__ " + "getter setter retain unsafe_unretained " + "nonnull nullable null_unspecified null_resettable class instancetype " + "NS_DESIGNATED_INITIALIZER NS_UNAVAILABLE NS_REQUIRES_SUPER " + "NS_RETURNS_INNER_POINTER NS_INLINE NS_AVAILABLE NS_DEPRECATED " + "NS_ENUM NS_OPTIONS NS_SWIFT_UNAVAILABLE " + "NS_ASSUME_NONNULL_BEGIN NS_ASSUME_NONNULL_END " + "NS_REFINED_FOR_SWIFT NS_SWIFT_NAME NS_SWIFT_NOTHROW " + "NS_DURING NS_HANDLER NS_ENDHANDLER NS_VALUERETURN NS_VOIDRETURN",
      literal: "false true FALSE TRUE nil YES NO NULL",
      built_in: "BOOL dispatch_once_t dispatch_queue_t dispatch_sync dispatch_async dispatch_once"
    };
    const CLASS_KEYWORDS = {
      $pattern: IDENTIFIER_RE,
      keyword: "@interface @class @protocol @implementation"
    };
    return {
      name: "Objective-C",
      aliases: [ "mm", "objc", "obj-c", "obj-c++", "objective-c++" ],
      keywords: OBJC_KEYWORDS,
      illegal: "</",
      contains: [ API_CLASS, hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, hljs.C_NUMBER_MODE, hljs.QUOTE_STRING_MODE, hljs.APOS_STRING_MODE, {
        className: "string",
        variants: [ {
          begin: '@"',
          end: '"',
          illegal: "\\n",
          contains: [ hljs.BACKSLASH_ESCAPE ]
        } ]
      }, {
        className: "meta",
        begin: /#\s*[a-z]+\b/,
        end: /$/,
        keywords: {
          "meta-keyword": "if else elif endif define undef warning error line " + "pragma ifdef ifndef include"
        },
        contains: [ {
          begin: /\\\n/,
          relevance: 0
        }, hljs.inherit(hljs.QUOTE_STRING_MODE, {
          className: "meta-string"
        }), {
          className: "meta-string",
          begin: /<.*?>/,
          end: /$/,
          illegal: "\\n"
        }, hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE ]
      }, {
        className: "class",
        begin: "(" + CLASS_KEYWORDS.keyword.split(" ").join("|") + ")\\b",
        end: /(\{|$)/,
        excludeEnd: true,
        keywords: CLASS_KEYWORDS,
        contains: [ hljs.UNDERSCORE_TITLE_MODE ]
      }, {
        begin: "\\." + hljs.UNDERSCORE_IDENT_RE,
        relevance: 0
      } ]
    };
  }
  var objectivec_1 = objectivec;
  /*
  Language: PHP
  Author: Victor Karamzin <Victor.Karamzin@enterra-inc.com>
  Contributors: Evgeny Stepanischev <imbolk@gmail.com>, Ivan Sagalaev <maniac@softwaremaniacs.org>
  Website: https://www.php.net
  Category: common
  */
  /**
   * @param {HLJSApi} hljs
   * @returns {LanguageDetail}
   * */  function php(hljs) {
    const VARIABLE = {
      className: "variable",
      begin: "\\$+[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*" + 
      // negative look-ahead tries to avoid matching patterns that are not
      // Perl at all like $ident$, @ident@, etc.
      `(?![A-Za-z0-9])(?![$])`
    };
    const PREPROCESSOR = {
      className: "meta",
      variants: [ {
        begin: /<\?php/,
        relevance: 10
      }, // boost for obvious PHP
      {
        begin: /<\?[=]?/
      }, {
        begin: /\?>/
      } ]
    };
    const SUBST = {
      className: "subst",
      variants: [ {
        begin: /\$\w+/
      }, {
        begin: /\{\$/,
        end: /\}/
      } ]
    };
    const SINGLE_QUOTED = hljs.inherit(hljs.APOS_STRING_MODE, {
      illegal: null
    });
    const DOUBLE_QUOTED = hljs.inherit(hljs.QUOTE_STRING_MODE, {
      illegal: null,
      contains: hljs.QUOTE_STRING_MODE.contains.concat(SUBST)
    });
    const HEREDOC = hljs.END_SAME_AS_BEGIN({
      begin: /<<<[ \t]*(\w+)\n/,
      end: /[ \t]*(\w+)\b/,
      contains: hljs.QUOTE_STRING_MODE.contains.concat(SUBST)
    });
    const STRING = {
      className: "string",
      contains: [ hljs.BACKSLASH_ESCAPE, PREPROCESSOR ],
      variants: [ hljs.inherit(SINGLE_QUOTED, {
        begin: "b'",
        end: "'"
      }), hljs.inherit(DOUBLE_QUOTED, {
        begin: 'b"',
        end: '"'
      }), DOUBLE_QUOTED, SINGLE_QUOTED, HEREDOC ]
    };
    const NUMBER = {
      variants: [ hljs.BINARY_NUMBER_MODE, hljs.C_NUMBER_MODE ]
    };
    const KEYWORDS = {
      keyword: 
      // Magic constants:
      // <https://www.php.net/manual/en/language.constants.predefined.php>
      "__CLASS__ __DIR__ __FILE__ __FUNCTION__ __LINE__ __METHOD__ __NAMESPACE__ __TRAIT__ " + 
      // Function that look like language construct or language construct that look like function:
      // List of keywords that may not require parenthesis
      "die echo exit include include_once print require require_once " + 
      // These are not language construct (function) but operate on the currently-executing function and can access the current symbol table
      // 'compact extract func_get_arg func_get_args func_num_args get_called_class get_parent_class ' +
      // Other keywords:
      // <https://www.php.net/manual/en/reserved.php>
      // <https://www.php.net/manual/en/language.types.type-juggling.php>
      "array abstract and as binary bool boolean break callable case catch class clone const continue declare " + "default do double else elseif empty enddeclare endfor endforeach endif endswitch endwhile eval extends " + "final finally float for foreach from global goto if implements instanceof insteadof int integer interface " + "isset iterable list match|0 new object or private protected public real return string switch throw trait " + "try unset use var void while xor yield",
      literal: "false null true",
      built_in: 
      // Standard PHP library:
      // <https://www.php.net/manual/en/book.spl.php>
      "Error|0 " + // error is too common a name esp since PHP is case in-sensitive
      "AppendIterator ArgumentCountError ArithmeticError ArrayIterator ArrayObject AssertionError BadFunctionCallException BadMethodCallException CachingIterator CallbackFilterIterator CompileError Countable DirectoryIterator DivisionByZeroError DomainException EmptyIterator ErrorException Exception FilesystemIterator FilterIterator GlobIterator InfiniteIterator InvalidArgumentException IteratorIterator LengthException LimitIterator LogicException MultipleIterator NoRewindIterator OutOfBoundsException OutOfRangeException OuterIterator OverflowException ParentIterator ParseError RangeException RecursiveArrayIterator RecursiveCachingIterator RecursiveCallbackFilterIterator RecursiveDirectoryIterator RecursiveFilterIterator RecursiveIterator RecursiveIteratorIterator RecursiveRegexIterator RecursiveTreeIterator RegexIterator RuntimeException SeekableIterator SplDoublyLinkedList SplFileInfo SplFileObject SplFixedArray SplHeap SplMaxHeap SplMinHeap SplObjectStorage SplObserver SplObserver SplPriorityQueue SplQueue SplStack SplSubject SplSubject SplTempFileObject TypeError UnderflowException UnexpectedValueException " + 
      // Reserved interfaces:
      // <https://www.php.net/manual/en/reserved.interfaces.php>
      "ArrayAccess Closure Generator Iterator IteratorAggregate Serializable Throwable Traversable WeakReference " + 
      // Reserved classes:
      // <https://www.php.net/manual/en/reserved.classes.php>
      "Directory __PHP_Incomplete_Class parent php_user_filter self static stdClass"
    };
    return {
      aliases: [ "php", "php3", "php4", "php5", "php6", "php7", "php8" ],
      case_insensitive: true,
      keywords: KEYWORDS,
      contains: [ hljs.HASH_COMMENT_MODE, hljs.COMMENT("//", "$", {
        contains: [ PREPROCESSOR ]
      }), hljs.COMMENT("/\\*", "\\*/", {
        contains: [ {
          className: "doctag",
          begin: "@[A-Za-z]+"
        } ]
      }), hljs.COMMENT("__halt_compiler.+?;", false, {
        endsWithParent: true,
        keywords: "__halt_compiler"
      }), PREPROCESSOR, {
        className: "keyword",
        begin: /\$this\b/
      }, VARIABLE, {
        // swallow composed identifiers to avoid parsing them as keywords
        begin: /(::|->)+[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*/
      }, {
        className: "function",
        relevance: 0,
        beginKeywords: "fn function",
        end: /[;{]/,
        excludeEnd: true,
        illegal: "[$%\\[]",
        contains: [ hljs.UNDERSCORE_TITLE_MODE, {
          begin: "=>"
        }, {
          className: "params",
          begin: "\\(",
          end: "\\)",
          excludeBegin: true,
          excludeEnd: true,
          keywords: KEYWORDS,
          contains: [ "self", VARIABLE, hljs.C_BLOCK_COMMENT_MODE, STRING, NUMBER ]
        } ]
      }, {
        className: "class",
        beginKeywords: "class interface",
        relevance: 0,
        end: /\{/,
        excludeEnd: true,
        illegal: /[:($"]/,
        contains: [ {
          beginKeywords: "extends implements"
        }, hljs.UNDERSCORE_TITLE_MODE ]
      }, {
        beginKeywords: "namespace",
        relevance: 0,
        end: ";",
        illegal: /[.']/,
        contains: [ hljs.UNDERSCORE_TITLE_MODE ]
      }, {
        beginKeywords: "use",
        relevance: 0,
        end: ";",
        contains: [ hljs.UNDERSCORE_TITLE_MODE ]
      }, STRING, NUMBER ]
    };
  }
  var php_1 = php;
  /*
  Language: Python
  Description: Python is an interpreted, object-oriented, high-level programming language with dynamic semantics.
  Website: https://www.python.org
  Category: common
  */  function python(hljs) {
    const RESERVED_WORDS = [ "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else", "except", "finally", "for", "", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal|10", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield" ];
    const BUILT_INS = [ "__import__", "abs", "all", "any", "ascii", "bin", "bool", "breakpoint", "bytearray", "bytes", "callable", "chr", "classmethod", "compile", "complex", "delattr", "dict", "dir", "divmod", "enumerate", "eval", "exec", "filter", "float", "format", "frozenset", "getattr", "globals", "hasattr", "hash", "help", "hex", "id", "input", "int", "isinstance", "issubclass", "iter", "len", "list", "locals", "map", "max", "memoryview", "min", "next", "object", "oct", "open", "ord", "pow", "print", "property", "range", "repr", "reversed", "round", "set", "setattr", "slice", "sorted", "staticmethod", "str", "sum", "super", "tuple", "type", "vars", "zip" ];
    const LITERALS = [ "__debug__", "Ellipsis", "False", "None", "NotImplemented", "True" ];
    const KEYWORDS = {
      keyword: RESERVED_WORDS.join(" "),
      built_in: BUILT_INS.join(" "),
      literal: LITERALS.join(" ")
    };
    const PROMPT = {
      className: "meta",
      begin: /^(>>>|\.\.\.) /
    };
    const SUBST = {
      className: "subst",
      begin: /\{/,
      end: /\}/,
      keywords: KEYWORDS,
      illegal: /#/
    };
    const LITERAL_BRACKET = {
      begin: /\{\{/,
      relevance: 0
    };
    const STRING = {
      className: "string",
      contains: [ hljs.BACKSLASH_ESCAPE ],
      variants: [ {
        begin: /([uU]|[bB]|[rR]|[bB][rR]|[rR][bB])?'''/,
        end: /'''/,
        contains: [ hljs.BACKSLASH_ESCAPE, PROMPT ],
        relevance: 10
      }, {
        begin: /([uU]|[bB]|[rR]|[bB][rR]|[rR][bB])?"""/,
        end: /"""/,
        contains: [ hljs.BACKSLASH_ESCAPE, PROMPT ],
        relevance: 10
      }, {
        begin: /([fF][rR]|[rR][fF]|[fF])'''/,
        end: /'''/,
        contains: [ hljs.BACKSLASH_ESCAPE, PROMPT, LITERAL_BRACKET, SUBST ]
      }, {
        begin: /([fF][rR]|[rR][fF]|[fF])"""/,
        end: /"""/,
        contains: [ hljs.BACKSLASH_ESCAPE, PROMPT, LITERAL_BRACKET, SUBST ]
      }, {
        begin: /([uU]|[rR])'/,
        end: /'/,
        relevance: 10
      }, {
        begin: /([uU]|[rR])"/,
        end: /"/,
        relevance: 10
      }, {
        begin: /([bB]|[bB][rR]|[rR][bB])'/,
        end: /'/
      }, {
        begin: /([bB]|[bB][rR]|[rR][bB])"/,
        end: /"/
      }, {
        begin: /([fF][rR]|[rR][fF]|[fF])'/,
        end: /'/,
        contains: [ hljs.BACKSLASH_ESCAPE, LITERAL_BRACKET, SUBST ]
      }, {
        begin: /([fF][rR]|[rR][fF]|[fF])"/,
        end: /"/,
        contains: [ hljs.BACKSLASH_ESCAPE, LITERAL_BRACKET, SUBST ]
      }, hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE ]
    };
    // https://docs.python.org/3.9/reference/lexical_analysis.html#numeric-literals
        const digitpart = "[0-9](_?[0-9])*";
    const pointfloat = `(\\b(${digitpart}))?\\.(${digitpart})|\\b(${digitpart})\\.`;
    const NUMBER = {
      className: "number",
      relevance: 0,
      variants: [ 
      // exponentfloat, pointfloat
      // https://docs.python.org/3.9/reference/lexical_analysis.html#floating-point-literals
      // optionally imaginary
      // https://docs.python.org/3.9/reference/lexical_analysis.html#imaginary-literals
      // Note: no leading \b because floats can start with a decimal point
      // and we don't want to mishandle e.g. `fn(.5)`,
      // no trailing \b for pointfloat because it can end with a decimal point
      // and we don't want to mishandle e.g. `0..hex()`; this should be safe
      // because both MUST contain a decimal point and so cannot be confused with
      // the interior part of an identifier
      {
        begin: `(\\b(${digitpart})|(${pointfloat}))[eE][+-]?(${digitpart})[jJ]?\\b`
      }, {
        begin: `(${pointfloat})[jJ]?`
      }, 
      // decinteger, bininteger, octinteger, hexinteger
      // https://docs.python.org/3.9/reference/lexical_analysis.html#integer-literals
      // optionally "long" in Python 2
      // https://docs.python.org/2.7/reference/lexical_analysis.html#integer-and-long-integer-literals
      // decinteger is optionally imaginary
      // https://docs.python.org/3.9/reference/lexical_analysis.html#imaginary-literals
      {
        begin: "\\b([1-9](_?[0-9])*|0+(_?0)*)[lLjJ]?\\b"
      }, {
        begin: "\\b0[bB](_?[01])+[lL]?\\b"
      }, {
        begin: "\\b0[oO](_?[0-7])+[lL]?\\b"
      }, {
        begin: "\\b0[xX](_?[0-9a-fA-F])+[lL]?\\b"
      }, 
      // imagnumber (digitpart-based)
      // https://docs.python.org/3.9/reference/lexical_analysis.html#imaginary-literals
      {
        begin: `\\b(${digitpart})[jJ]\\b`
      } ]
    };
    const PARAMS = {
      className: "params",
      variants: [ 
      // Exclude params at functions without params
      {
        begin: /\(\s*\)/,
        skip: true,
        className: null
      }, {
        begin: /\(/,
        end: /\)/,
        excludeBegin: true,
        excludeEnd: true,
        keywords: KEYWORDS,
        contains: [ "self", PROMPT, NUMBER, STRING, hljs.HASH_COMMENT_MODE ]
      } ]
    };
    SUBST.contains = [ STRING, NUMBER, PROMPT ];
    return {
      name: "Python",
      aliases: [ "py", "gyp", "ipython" ],
      keywords: KEYWORDS,
      illegal: /(<\/|->|\?)|=>/,
      contains: [ PROMPT, NUMBER, 
      // eat "if" prior to string so that it won't accidentally be
      // labeled as an f-string as in:
      {
        begin: /\bself\b/
      }, // very common convention
      {
        beginKeywords: "if",
        relevance: 0
      }, STRING, hljs.HASH_COMMENT_MODE, {
        variants: [ {
          className: "function",
          beginKeywords: "def"
        }, {
          className: "class",
          beginKeywords: "class"
        } ],
        end: /:/,
        illegal: /[${=;\n,]/,
        contains: [ hljs.UNDERSCORE_TITLE_MODE, PARAMS, {
          begin: /->/,
          endsWithParent: true,
          keywords: "None"
        } ]
      }, {
        className: "meta",
        begin: /^[\t ]*@/,
        end: /(?=#)|$/,
        contains: [ NUMBER, PARAMS, STRING ]
      }, {
        begin: /\b(print|exec)\(/
      } ]
    };
  }
  var python_1 = python;
  /*
  Language: Rust
  Author: Andrey Vlasovskikh <andrey.vlasovskikh@gmail.com>
  Contributors: Roman Shmatov <romanshmatov@gmail.com>, Kasper Andersen <kma_untrusted@protonmail.com>
  Website: https://www.rust-lang.org
  Category: common, system
  */  function rust(hljs) {
    const NUM_SUFFIX = "([ui](8|16|32|64|128|size)|f(32|64))?";
    const KEYWORDS = "abstract as async await become box break const continue crate do dyn " + "else enum extern false final fn for if impl in let loop macro match mod " + "move mut override priv pub ref return self Self static struct super " + "trait true try type typeof unsafe unsized use virtual where while yield";
    const BUILTINS = 
    // functions
    "drop " + 
    // types
    "i8 i16 i32 i64 i128 isize " + "u8 u16 u32 u64 u128 usize " + "f32 f64 " + "str char bool " + "Box Option Result String Vec " + 
    // traits
    "Copy Send Sized Sync Drop Fn FnMut FnOnce ToOwned Clone Debug " + "PartialEq PartialOrd Eq Ord AsRef AsMut Into From Default Iterator " + "Extend IntoIterator DoubleEndedIterator ExactSizeIterator " + "SliceConcatExt ToString " + 
    // macros
    "assert! assert_eq! bitflags! bytes! cfg! col! concat! concat_idents! " + "debug_assert! debug_assert_eq! env! panic! file! format! format_args! " + "include_bin! include_str! line! local_data_key! module_path! " + "option_env! print! println! select! stringify! try! unimplemented! " + "unreachable! vec! write! writeln! macro_rules! assert_ne! debug_assert_ne!";
    return {
      name: "Rust",
      aliases: [ "rs" ],
      keywords: {
        $pattern: hljs.IDENT_RE + "!?",
        keyword: KEYWORDS,
        literal: "true false Some None Ok Err",
        built_in: BUILTINS
      },
      illegal: "</",
      contains: [ hljs.C_LINE_COMMENT_MODE, hljs.COMMENT("/\\*", "\\*/", {
        contains: [ "self" ]
      }), hljs.inherit(hljs.QUOTE_STRING_MODE, {
        begin: /b?"/,
        illegal: null
      }), {
        className: "string",
        variants: [ {
          begin: /r(#*)"(.|\n)*?"\1(?!#)/
        }, {
          begin: /b?'\\?(x\w{2}|u\w{4}|U\w{8}|.)'/
        } ]
      }, {
        className: "symbol",
        begin: /'[a-zA-Z_][a-zA-Z0-9_]*/
      }, {
        className: "number",
        variants: [ {
          begin: "\\b0b([01_]+)" + NUM_SUFFIX
        }, {
          begin: "\\b0o([0-7_]+)" + NUM_SUFFIX
        }, {
          begin: "\\b0x([A-Fa-f0-9_]+)" + NUM_SUFFIX
        }, {
          begin: "\\b(\\d[\\d_]*(\\.[0-9_]+)?([eE][+-]?[0-9_]+)?)" + NUM_SUFFIX
        } ],
        relevance: 0
      }, {
        className: "function",
        beginKeywords: "fn",
        end: "(\\(|<)",
        excludeEnd: true,
        contains: [ hljs.UNDERSCORE_TITLE_MODE ]
      }, {
        className: "meta",
        begin: "#!?\\[",
        end: "\\]",
        contains: [ {
          className: "meta-string",
          begin: /"/,
          end: /"/
        } ]
      }, {
        className: "class",
        beginKeywords: "type",
        end: ";",
        contains: [ hljs.inherit(hljs.UNDERSCORE_TITLE_MODE, {
          endsParent: true
        }) ],
        illegal: "\\S"
      }, {
        className: "class",
        beginKeywords: "trait enum struct union",
        end: /\{/,
        contains: [ hljs.inherit(hljs.UNDERSCORE_TITLE_MODE, {
          endsParent: true
        }) ],
        illegal: "[\\w\\d]"
      }, {
        begin: hljs.IDENT_RE + "::",
        keywords: {
          built_in: BUILTINS
        }
      }, {
        begin: "->"
      } ]
    };
  }
  var rust_1 = rust;
  /*
  Language: Scala
  Category: functional
  Author: Jan Berkel <jan.berkel@gmail.com>
  Contributors: Erik Osheim <d_m@plastic-idolatry.com>
  Website: https://www.scala-lang.org
  */  function scala(hljs) {
    const ANNOTATION = {
      className: "meta",
      begin: "@[A-Za-z]+"
    };
    // used in strings for escaping/interpolation/substitution
        const SUBST = {
      className: "subst",
      variants: [ {
        begin: "\\$[A-Za-z0-9_]+"
      }, {
        begin: /\$\{/,
        end: /\}/
      } ]
    };
    const STRING = {
      className: "string",
      variants: [ {
        begin: '"',
        end: '"',
        illegal: "\\n",
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        begin: '"""',
        end: '"""',
        relevance: 10
      }, {
        begin: '[a-z]+"',
        end: '"',
        illegal: "\\n",
        contains: [ hljs.BACKSLASH_ESCAPE, SUBST ]
      }, {
        className: "string",
        begin: '[a-z]+"""',
        end: '"""',
        contains: [ SUBST ],
        relevance: 10
      } ]
    };
    const SYMBOL = {
      className: "symbol",
      begin: "'\\w[\\w\\d_]*(?!')"
    };
    const TYPE = {
      className: "type",
      begin: "\\b[A-Z][A-Za-z0-9_]*",
      relevance: 0
    };
    const NAME = {
      className: "title",
      begin: /[^0-9\n\t "'(),.`{}\[\]:;][^\n\t "'(),.`{}\[\]:;]+|[^0-9\n\t "'(),.`{}\[\]:;=]/,
      relevance: 0
    };
    const CLASS = {
      className: "class",
      beginKeywords: "class object trait type",
      end: /[:={\[\n;]/,
      excludeEnd: true,
      contains: [ hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, {
        beginKeywords: "extends with",
        relevance: 10
      }, {
        begin: /\[/,
        end: /\]/,
        excludeBegin: true,
        excludeEnd: true,
        relevance: 0,
        contains: [ TYPE ]
      }, {
        className: "params",
        begin: /\(/,
        end: /\)/,
        excludeBegin: true,
        excludeEnd: true,
        relevance: 0,
        contains: [ TYPE ]
      }, NAME ]
    };
    const METHOD = {
      className: "function",
      beginKeywords: "def",
      end: /[:={\[(\n;]/,
      excludeEnd: true,
      contains: [ NAME ]
    };
    return {
      name: "Scala",
      keywords: {
        literal: "true false null",
        keyword: "type yield lazy override def with val var sealed abstract private trait object if forSome for while throw finally protected extends import final return else break new catch super class case package default try this match continue throws implicit"
      },
      contains: [ hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, STRING, SYMBOL, TYPE, METHOD, CLASS, hljs.C_NUMBER_MODE, ANNOTATION ]
    };
  }
  var scala_1 = scala;
  /*
  Language: Scheme
  Description: Scheme is a programming language in the Lisp family.
               (keywords based on http://community.schemewiki.org/?scheme-keywords)
  Author: JP Verkamp <me@jverkamp.com>
  Contributors: Ivan Sagalaev <maniac@softwaremaniacs.org>
  Origin: clojure.js
  Website: http://community.schemewiki.org/?what-is-scheme
  Category: lisp
  */  function scheme(hljs) {
    var SCHEME_IDENT_RE = "[^\\(\\)\\[\\]\\{\\}\",'`;#|\\\\\\s]+";
    var SCHEME_SIMPLE_NUMBER_RE = "(-|\\+)?\\d+([./]\\d+)?";
    var SCHEME_COMPLEX_NUMBER_RE = SCHEME_SIMPLE_NUMBER_RE + "[+\\-]" + SCHEME_SIMPLE_NUMBER_RE + "i";
    var KEYWORDS = {
      $pattern: SCHEME_IDENT_RE,
      "builtin-name": "case-lambda call/cc class define-class exit-handler field import " + "inherit init-field interface let*-values let-values let/ec mixin " + "opt-lambda override protect provide public rename require " + "require-for-syntax syntax syntax-case syntax-error unit/sig unless " + "when with-syntax and begin call-with-current-continuation " + "call-with-input-file call-with-output-file case cond define " + "define-syntax delay do dynamic-wind else for-each if lambda let let* " + "let-syntax letrec letrec-syntax map or syntax-rules ' * + , ,@ - ... / " + "; < <= = => > >= ` abs acos angle append apply asin assoc assq assv atan " + "boolean? caar cadr call-with-input-file call-with-output-file " + "call-with-values car cdddar cddddr cdr ceiling char->integer " + "char-alphabetic? char-ci<=? char-ci<? char-ci=? char-ci>=? char-ci>? " + "char-downcase char-lower-case? char-numeric? char-ready? char-upcase " + "char-upper-case? char-whitespace? char<=? char<? char=? char>=? char>? " + "char? close-input-port close-output-port complex? cons cos " + "current-input-port current-output-port denominator display eof-object? " + "eq? equal? eqv? eval even? exact->inexact exact? exp expt floor " + "force gcd imag-part inexact->exact inexact? input-port? integer->char " + "integer? interaction-environment lcm length list list->string " + "list->vector list-ref list-tail list? load log magnitude make-polar " + "make-rectangular make-string make-vector max member memq memv min " + "modulo negative? newline not null-environment null? number->string " + "number? numerator odd? open-input-file open-output-file output-port? " + "pair? peek-char port? positive? procedure? quasiquote quote quotient " + "rational? rationalize read read-char real-part real? remainder reverse " + "round scheme-report-environment set! set-car! set-cdr! sin sqrt string " + "string->list string->number string->symbol string-append string-ci<=? " + "string-ci<? string-ci=? string-ci>=? string-ci>? string-copy " + "string-fill! string-length string-ref string-set! string<=? string<? " + "string=? string>=? string>? string? substring symbol->string symbol? " + "tan transcript-off transcript-on truncate values vector " + "vector->list vector-fill! vector-length vector-ref vector-set! " + "with-input-from-file with-output-to-file write write-char zero?"
    };
    var LITERAL = {
      className: "literal",
      begin: "(#t|#f|#\\\\" + SCHEME_IDENT_RE + "|#\\\\.)"
    };
    var NUMBER = {
      className: "number",
      variants: [ {
        begin: SCHEME_SIMPLE_NUMBER_RE,
        relevance: 0
      }, {
        begin: SCHEME_COMPLEX_NUMBER_RE,
        relevance: 0
      }, {
        begin: "#b[0-1]+(/[0-1]+)?"
      }, {
        begin: "#o[0-7]+(/[0-7]+)?"
      }, {
        begin: "#x[0-9a-f]+(/[0-9a-f]+)?"
      } ]
    };
    var STRING = hljs.QUOTE_STRING_MODE;
    var COMMENT_MODES = [ hljs.COMMENT(";", "$", {
      relevance: 0
    }), hljs.COMMENT("#\\|", "\\|#") ];
    var IDENT = {
      begin: SCHEME_IDENT_RE,
      relevance: 0
    };
    var QUOTED_IDENT = {
      className: "symbol",
      begin: "'" + SCHEME_IDENT_RE
    };
    var BODY = {
      endsWithParent: true,
      relevance: 0
    };
    var QUOTED_LIST = {
      variants: [ {
        begin: /'/
      }, {
        begin: "`"
      } ],
      contains: [ {
        begin: "\\(",
        end: "\\)",
        contains: [ "self", LITERAL, STRING, NUMBER, IDENT, QUOTED_IDENT ]
      } ]
    };
    var NAME = {
      className: "name",
      relevance: 0,
      begin: SCHEME_IDENT_RE,
      keywords: KEYWORDS
    };
    var LAMBDA = {
      begin: /lambda/,
      endsWithParent: true,
      returnBegin: true,
      contains: [ NAME, {
        begin: /\(/,
        end: /\)/,
        endsParent: true,
        contains: [ IDENT ]
      } ]
    };
    var LIST = {
      variants: [ {
        begin: "\\(",
        end: "\\)"
      }, {
        begin: "\\[",
        end: "\\]"
      } ],
      contains: [ LAMBDA, NAME, BODY ]
    };
    BODY.contains = [ LITERAL, NUMBER, STRING, IDENT, QUOTED_IDENT, QUOTED_LIST, LIST ].concat(COMMENT_MODES);
    return {
      name: "Scheme",
      illegal: /\S/,
      contains: [ hljs.SHEBANG(), NUMBER, STRING, QUOTED_IDENT, QUOTED_LIST, LIST ].concat(COMMENT_MODES)
    };
  }
  var scheme_1 = scheme;
  /*
  Language: SCSS
  Description: Scss is an extension of the syntax of CSS.
  Author: Kurt Emch <kurt@kurtemch.com>
  Website: https://sass-lang.com
  Category: common, css
  */  function scss(hljs) {
    var AT_IDENTIFIER = "@[a-z-]+";
 // @font-face
        var AT_MODIFIERS = "and or not only";
    var IDENT_RE = "[a-zA-Z-][a-zA-Z0-9_-]*";
    var VARIABLE = {
      className: "variable",
      begin: "(\\$" + IDENT_RE + ")\\b"
    };
    var HEXCOLOR = {
      className: "number",
      begin: "#[0-9A-Fa-f]+"
    };
    var DEF_INTERNALS = {
      className: "attribute",
      begin: "[A-Z\\_\\.\\-]+",
      end: ":",
      excludeEnd: true,
      illegal: "[^\\s]",
      starts: {
        endsWithParent: true,
        excludeEnd: true,
        contains: [ HEXCOLOR, hljs.CSS_NUMBER_MODE, hljs.QUOTE_STRING_MODE, hljs.APOS_STRING_MODE, hljs.C_BLOCK_COMMENT_MODE, {
          className: "meta",
          begin: "!important"
        } ]
      }
    };
    return {
      name: "SCSS",
      case_insensitive: true,
      illegal: "[=/|']",
      contains: [ hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, {
        className: "selector-id",
        begin: "#[A-Za-z0-9_-]+",
        relevance: 0
      }, {
        className: "selector-class",
        begin: "\\.[A-Za-z0-9_-]+",
        relevance: 0
      }, {
        className: "selector-attr",
        begin: "\\[",
        end: "\\]",
        illegal: "$"
      }, {
        className: "selector-tag",
        // begin: IDENT_RE, end: '[,|\\s]'
        begin: "\\b(a|abbr|acronym|address|area|article|aside|audio|b|base|big|blockquote|body|br|button|canvas|caption|cite|code|col|colgroup|command|datalist|dd|del|details|dfn|div|dl|dt|em|embed|fieldset|figcaption|figure|footer|form|frame|frameset|(h[1-6])|head|header|hgroup|hr|html|i|iframe|img|input|ins|kbd|keygen|label|legend|li|link|map|mark|meta|meter|nav|noframes|noscript|object|ol|optgroup|option|output|p|param|pre|progress|q|rp|rt|ruby|samp|script|section|select|small|span|strike|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|time|title|tr|tt|ul|var|video)\\b",
        relevance: 0
      }, {
        className: "selector-pseudo",
        begin: ":(visited|valid|root|right|required|read-write|read-only|out-range|optional|only-of-type|only-child|nth-of-type|nth-last-of-type|nth-last-child|nth-child|not|link|left|last-of-type|last-child|lang|invalid|indeterminate|in-range|hover|focus|first-of-type|first-line|first-letter|first-child|first|enabled|empty|disabled|default|checked|before|after|active)"
      }, {
        className: "selector-pseudo",
        begin: "::(after|before|choices|first-letter|first-line|repeat-index|repeat-item|selection|value)"
      }, VARIABLE, {
        className: "attribute",
        begin: "\\b(src|z-index|word-wrap|word-spacing|word-break|width|widows|white-space|visibility|vertical-align|unicode-bidi|transition-timing-function|transition-property|transition-duration|transition-delay|transition|transform-style|transform-origin|transform|top|text-underline-position|text-transform|text-shadow|text-rendering|text-overflow|text-indent|text-decoration-style|text-decoration-line|text-decoration-color|text-decoration|text-align-last|text-align|tab-size|table-layout|right|resize|quotes|position|pointer-events|perspective-origin|perspective|page-break-inside|page-break-before|page-break-after|padding-top|padding-right|padding-left|padding-bottom|padding|overflow-y|overflow-x|overflow-wrap|overflow|outline-width|outline-style|outline-offset|outline-color|outline|orphans|order|opacity|object-position|object-fit|normal|none|nav-up|nav-right|nav-left|nav-index|nav-down|min-width|min-height|max-width|max-height|mask|marks|margin-top|margin-right|margin-left|margin-bottom|margin|list-style-type|list-style-position|list-style-image|list-style|line-height|letter-spacing|left|justify-content|initial|inherit|ime-mode|image-orientation|image-resolution|image-rendering|icon|hyphens|height|font-weight|font-variant-ligatures|font-variant|font-style|font-stretch|font-size-adjust|font-size|font-language-override|font-kerning|font-feature-settings|font-family|font|float|flex-wrap|flex-shrink|flex-grow|flex-flow|flex-direction|flex-basis|flex|filter|empty-cells|display|direction|cursor|counter-reset|counter-increment|content|column-width|column-span|column-rule-width|column-rule-style|column-rule-color|column-rule|column-gap|column-fill|column-count|columns|color|clip-path|clip|clear|caption-side|break-inside|break-before|break-after|box-sizing|box-shadow|box-decoration-break|bottom|border-width|border-top-width|border-top-style|border-top-right-radius|border-top-left-radius|border-top-color|border-top|border-style|border-spacing|border-right-width|border-right-style|border-right-color|border-right|border-radius|border-left-width|border-left-style|border-left-color|border-left|border-image-width|border-image-source|border-image-slice|border-image-repeat|border-image-outset|border-image|border-color|border-collapse|border-bottom-width|border-bottom-style|border-bottom-right-radius|border-bottom-left-radius|border-bottom-color|border-bottom|border|background-size|background-repeat|background-position|background-origin|background-image|background-color|background-clip|background-attachment|background-blend-mode|background|backface-visibility|auto|animation-timing-function|animation-play-state|animation-name|animation-iteration-count|animation-fill-mode|animation-duration|animation-direction|animation-delay|animation|align-self|align-items|align-content)\\b",
        illegal: "[^\\s]"
      }, {
        begin: "\\b(whitespace|wait|w-resize|visible|vertical-text|vertical-ideographic|uppercase|upper-roman|upper-alpha|underline|transparent|top|thin|thick|text|text-top|text-bottom|tb-rl|table-header-group|table-footer-group|sw-resize|super|strict|static|square|solid|small-caps|separate|se-resize|scroll|s-resize|rtl|row-resize|ridge|right|repeat|repeat-y|repeat-x|relative|progress|pointer|overline|outside|outset|oblique|nowrap|not-allowed|normal|none|nw-resize|no-repeat|no-drop|newspaper|ne-resize|n-resize|move|middle|medium|ltr|lr-tb|lowercase|lower-roman|lower-alpha|loose|list-item|line|line-through|line-edge|lighter|left|keep-all|justify|italic|inter-word|inter-ideograph|inside|inset|inline|inline-block|inherit|inactive|ideograph-space|ideograph-parenthesis|ideograph-numeric|ideograph-alpha|horizontal|hidden|help|hand|groove|fixed|ellipsis|e-resize|double|dotted|distribute|distribute-space|distribute-letter|distribute-all-lines|disc|disabled|default|decimal|dashed|crosshair|collapse|col-resize|circle|char|center|capitalize|break-word|break-all|bottom|both|bolder|bold|block|bidi-override|below|baseline|auto|always|all-scroll|absolute|table|table-cell)\\b"
      }, {
        begin: ":",
        end: ";",
        contains: [ VARIABLE, HEXCOLOR, hljs.CSS_NUMBER_MODE, hljs.QUOTE_STRING_MODE, hljs.APOS_STRING_MODE, {
          className: "meta",
          begin: "!important"
        } ]
      }, 
      // matching these here allows us to treat them more like regular CSS
      // rules so everything between the {} gets regular rule highlighting,
      // which is what we want for page and font-face
      {
        begin: "@(page|font-face)",
        lexemes: AT_IDENTIFIER,
        keywords: "@page @font-face"
      }, {
        begin: "@",
        end: "[{;]",
        returnBegin: true,
        keywords: AT_MODIFIERS,
        contains: [ {
          begin: AT_IDENTIFIER,
          className: "keyword"
        }, VARIABLE, hljs.QUOTE_STRING_MODE, hljs.APOS_STRING_MODE, HEXCOLOR, hljs.CSS_NUMBER_MODE ]
      } ]
    };
  }
  var scss_1 = scss;
  /*
  Language: Smalltalk
  Description: Smalltalk is an object-oriented, dynamically typed reflective programming language.
  Author: Vladimir Gubarkov <xonixx@gmail.com>
  Website: https://en.wikipedia.org/wiki/Smalltalk
  */  function smalltalk(hljs) {
    const VAR_IDENT_RE = "[a-z][a-zA-Z0-9_]*";
    const CHAR = {
      className: "string",
      begin: "\\$.{1}"
    };
    const SYMBOL = {
      className: "symbol",
      begin: "#" + hljs.UNDERSCORE_IDENT_RE
    };
    return {
      name: "Smalltalk",
      aliases: [ "st" ],
      keywords: "self super nil true false thisContext",
      // only 6
      contains: [ hljs.COMMENT('"', '"'), hljs.APOS_STRING_MODE, {
        className: "type",
        begin: "\\b[A-Z][A-Za-z0-9_]*",
        relevance: 0
      }, {
        begin: VAR_IDENT_RE + ":",
        relevance: 0
      }, hljs.C_NUMBER_MODE, SYMBOL, CHAR, {
        // This looks more complicated than needed to avoid combinatorial
        // explosion under V8. It effectively means `| var1 var2 ... |` with
        // whitespace adjacent to `|` being optional.
        begin: "\\|[ ]*" + VAR_IDENT_RE + "([ ]+" + VAR_IDENT_RE + ")*[ ]*\\|",
        returnBegin: true,
        end: /\|/,
        illegal: /\S/,
        contains: [ {
          begin: "(\\|[ ]*)?" + VAR_IDENT_RE
        } ]
      }, {
        begin: "#\\(",
        end: "\\)",
        contains: [ hljs.APOS_STRING_MODE, CHAR, hljs.C_NUMBER_MODE, SYMBOL ]
      } ]
    };
  }
  var smalltalk_1 = smalltalk;
  /*
  Language: Stylus
  Author: Bryant Williams <b.n.williams@gmail.com>
  Description: Stylus is an expressive, robust, feature-rich CSS language built for nodejs.
  Website: https://github.com/stylus/stylus
  Category: css
  */  function stylus(hljs) {
    var VARIABLE = {
      className: "variable",
      begin: "\\$" + hljs.IDENT_RE
    };
    var HEX_COLOR = {
      className: "number",
      begin: "#([a-fA-F0-9]{6}|[a-fA-F0-9]{3})"
    };
    var AT_KEYWORDS = [ "charset", "css", "debug", "extend", "font-face", "for", "import", "include", "media", "mixin", "page", "warn", "while" ];
    var PSEUDO_SELECTORS = [ "after", "before", "first-letter", "first-line", "active", "first-child", "focus", "hover", "lang", "link", "visited" ];
    var TAGS = [ "a", "abbr", "address", "article", "aside", "audio", "b", "blockquote", "body", "button", "canvas", "caption", "cite", "code", "dd", "del", "details", "dfn", "div", "dl", "dt", "em", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "html", "i", "iframe", "img", "input", "ins", "kbd", "label", "legend", "li", "mark", "menu", "nav", "object", "ol", "p", "q", "quote", "samp", "section", "span", "strong", "summary", "sup", "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "time", "tr", "ul", "var", "video" ];
    var LOOKAHEAD_TAG_END = "(?=[.\\s\\n[:,])";
    var ATTRIBUTES = [ "align-content", "align-items", "align-self", "animation", "animation-delay", "animation-direction", "animation-duration", "animation-fill-mode", "animation-iteration-count", "animation-name", "animation-play-state", "animation-timing-function", "auto", "backface-visibility", "background", "background-attachment", "background-clip", "background-color", "background-image", "background-origin", "background-position", "background-repeat", "background-size", "border", "border-bottom", "border-bottom-color", "border-bottom-left-radius", "border-bottom-right-radius", "border-bottom-style", "border-bottom-width", "border-collapse", "border-color", "border-image", "border-image-outset", "border-image-repeat", "border-image-slice", "border-image-source", "border-image-width", "border-left", "border-left-color", "border-left-style", "border-left-width", "border-radius", "border-right", "border-right-color", "border-right-style", "border-right-width", "border-spacing", "border-style", "border-top", "border-top-color", "border-top-left-radius", "border-top-right-radius", "border-top-style", "border-top-width", "border-width", "bottom", "box-decoration-break", "box-shadow", "box-sizing", "break-after", "break-before", "break-inside", "caption-side", "clear", "clip", "clip-path", "color", "column-count", "column-fill", "column-gap", "column-rule", "column-rule-color", "column-rule-style", "column-rule-width", "column-span", "column-width", "columns", "content", "counter-increment", "counter-reset", "cursor", "direction", "display", "empty-cells", "filter", "flex", "flex-basis", "flex-direction", "flex-flow", "flex-grow", "flex-shrink", "flex-wrap", "float", "font", "font-family", "font-feature-settings", "font-kerning", "font-language-override", "font-size", "font-size-adjust", "font-stretch", "font-style", "font-variant", "font-variant-ligatures", "font-weight", "height", "hyphens", "icon", "image-orientation", "image-rendering", "image-resolution", "ime-mode", "inherit", "initial", "justify-content", "left", "letter-spacing", "line-height", "list-style", "list-style-image", "list-style-position", "list-style-type", "margin", "margin-bottom", "margin-left", "margin-right", "margin-top", "marks", "mask", "max-height", "max-width", "min-height", "min-width", "nav-down", "nav-index", "nav-left", "nav-right", "nav-up", "none", "normal", "object-fit", "object-position", "opacity", "order", "orphans", "outline", "outline-color", "outline-offset", "outline-style", "outline-width", "overflow", "overflow-wrap", "overflow-x", "overflow-y", "padding", "padding-bottom", "padding-left", "padding-right", "padding-top", "page-break-after", "page-break-before", "page-break-inside", "perspective", "perspective-origin", "pointer-events", "position", "quotes", "resize", "right", "tab-size", "table-layout", "text-align", "text-align-last", "text-decoration", "text-decoration-color", "text-decoration-line", "text-decoration-style", "text-indent", "text-overflow", "text-rendering", "text-shadow", "text-transform", "text-underline-position", "top", "transform", "transform-origin", "transform-style", "transition", "transition-delay", "transition-duration", "transition-property", "transition-timing-function", "unicode-bidi", "vertical-align", "visibility", "white-space", "widows", "width", "word-break", "word-spacing", "word-wrap", "z-index" ];
    // illegals
        var ILLEGAL = [ "\\?", "(\\bReturn\\b)", // monkey
    "(\\bEnd\\b)", // monkey
    "(\\bend\\b)", // vbscript
    "(\\bdef\\b)", // gradle
    ";", // a whole lot of languages
    "#\\s", // markdown
    "\\*\\s", // markdown
    "===\\s", // markdown
    "\\|", "%" ];
    return {
      name: "Stylus",
      aliases: [ "styl" ],
      case_insensitive: false,
      keywords: "if else for in",
      illegal: "(" + ILLEGAL.join("|") + ")",
      contains: [ 
      // strings
      hljs.QUOTE_STRING_MODE, hljs.APOS_STRING_MODE, 
      // comments
      hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE, 
      // hex colors
      HEX_COLOR, 
      // class tag
      {
        begin: "\\.[a-zA-Z][a-zA-Z0-9_-]*" + LOOKAHEAD_TAG_END,
        className: "selector-class"
      }, 
      // id tag
      {
        begin: "#[a-zA-Z][a-zA-Z0-9_-]*" + LOOKAHEAD_TAG_END,
        className: "selector-id"
      }, 
      // tags
      {
        begin: "\\b(" + TAGS.join("|") + ")" + LOOKAHEAD_TAG_END,
        className: "selector-tag"
      }, 
      // psuedo selectors
      {
        begin: "&?:?:\\b(" + PSEUDO_SELECTORS.join("|") + ")" + LOOKAHEAD_TAG_END
      }, 
      // @ keywords
      {
        begin: "@(" + AT_KEYWORDS.join("|") + ")\\b"
      }, 
      // variables
      VARIABLE, 
      // dimension
      hljs.CSS_NUMBER_MODE, 
      // number
      hljs.NUMBER_MODE, 
      // functions
      //  - only from beginning of line + whitespace
      {
        className: "function",
        begin: "^[a-zA-Z][a-zA-Z0-9_-]*\\(.*\\)",
        illegal: "[\\n]",
        returnBegin: true,
        contains: [ {
          className: "title",
          begin: "\\b[a-zA-Z][a-zA-Z0-9_-]*"
        }, {
          className: "params",
          begin: /\(/,
          end: /\)/,
          contains: [ HEX_COLOR, VARIABLE, hljs.APOS_STRING_MODE, hljs.CSS_NUMBER_MODE, hljs.NUMBER_MODE, hljs.QUOTE_STRING_MODE ]
        } ]
      }, 
      // attributes
      //  - only from beginning of line + whitespace
      //  - must have whitespace after it
      {
        className: "attribute",
        begin: "\\b(" + ATTRIBUTES.reverse().join("|") + ")\\b",
        starts: {
          // value container
          end: /;|$/,
          contains: [ HEX_COLOR, VARIABLE, hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, hljs.CSS_NUMBER_MODE, hljs.NUMBER_MODE, hljs.C_BLOCK_COMMENT_MODE ],
          illegal: /\./,
          relevance: 0
        }
      } ]
    };
  }
  var stylus_1 = stylus;
  /*
  Language: Swift
  Description: Swift is a general-purpose programming language built using a modern approach to safety, performance, and software design patterns.
  Author: Chris Eidhof <chris@eidhof.nl>
  Contributors: Nate Cook <natecook@gmail.com>, Alexander Lichter <manniL@gmx.net>
  Website: https://swift.org
  Category: common, system
  */  function swift(hljs) {
    var SWIFT_KEYWORDS = {
      // override the pattern since the default of of /\w+/ is not sufficient to
      // capture the keywords that start with the character "#"
      $pattern: /[\w#]+/,
      keyword: "#available #colorLiteral #column #else #elseif #endif #file " + "#fileLiteral #function #if #imageLiteral #line #selector #sourceLocation " + "_ __COLUMN__ __FILE__ __FUNCTION__ __LINE__ Any as as! as? associatedtype " + "associativity break case catch class continue convenience default defer deinit didSet do " + "dynamic dynamicType else enum extension fallthrough false fileprivate final for func " + "get guard if import in indirect infix init inout internal is lazy left let " + "mutating nil none nonmutating open operator optional override postfix precedence " + "prefix private protocol Protocol public repeat required rethrows return " + "right self Self set some static struct subscript super switch throw throws true " + "try try! try? Type typealias unowned var weak where while willSet",
      literal: "true false nil",
      built_in: "abs advance alignof alignofValue anyGenerator assert assertionFailure " + "bridgeFromObjectiveC bridgeFromObjectiveCUnconditional bridgeToObjectiveC " + "bridgeToObjectiveCUnconditional c compactMap contains count countElements countLeadingZeros " + "debugPrint debugPrintln distance dropFirst dropLast dump encodeBitsAsWords " + "enumerate equal fatalError filter find getBridgedObjectiveCType getVaList " + "indices insertionSort isBridgedToObjectiveC isBridgedVerbatimToObjectiveC " + "isUniquelyReferenced isUniquelyReferencedNonObjC join lazy lexicographicalCompare " + "map max maxElement min minElement numericCast overlaps partition posix " + "precondition preconditionFailure print println quickSort readLine reduce reflect " + "reinterpretCast reverse roundUpToAlignment sizeof sizeofValue sort split " + "startsWith stride strideof strideofValue swap toString transcode " + "underestimateCount unsafeAddressOf unsafeBitCast unsafeDowncast unsafeUnwrap " + "unsafeReflect withExtendedLifetime withObjectAtPlusZero withUnsafePointer " + "withUnsafePointerToObject withUnsafeMutablePointer withUnsafeMutablePointers " + "withUnsafePointer withUnsafePointers withVaList zip"
    };
    var TYPE = {
      className: "type",
      begin: "\\b[A-Z][\\w\xc0-\u02b8']*",
      relevance: 0
    };
    // slightly more special to swift
        var OPTIONAL_USING_TYPE = {
      className: "type",
      begin: "\\b[A-Z][\\w\xc0-\u02b8']*[!?]"
    };
    var BLOCK_COMMENT = hljs.COMMENT("/\\*", "\\*/", {
      contains: [ "self" ]
    });
    var SUBST = {
      className: "subst",
      begin: /\\\(/,
      end: "\\)",
      keywords: SWIFT_KEYWORDS,
      contains: []
    };
    var STRING = {
      className: "string",
      contains: [ hljs.BACKSLASH_ESCAPE, SUBST ],
      variants: [ {
        begin: /"""/,
        end: /"""/
      }, {
        begin: /"/,
        end: /"/
      } ]
    };
    // https://docs.swift.org/swift-book/ReferenceManual/LexicalStructure.html#grammar_numeric-literal
    // TODO: Update for leading `-` after lookbehind is supported everywhere
        var decimalDigits = "([0-9]_*)+";
    var hexDigits = "([0-9a-fA-F]_*)+";
    var NUMBER = {
      className: "number",
      relevance: 0,
      variants: [ 
      // decimal floating-point-literal (subsumes decimal-literal)
      {
        begin: `\\b(${decimalDigits})(\\.(${decimalDigits}))?` + `([eE][+-]?(${decimalDigits}))?\\b`
      }, 
      // hexadecimal floating-point-literal (subsumes hexadecimal-literal)
      {
        begin: `\\b0x(${hexDigits})(\\.(${hexDigits}))?` + `([pP][+-]?(${decimalDigits}))?\\b`
      }, 
      // octal-literal
      {
        begin: /\b0o([0-7]_*)+\b/
      }, 
      // binary-literal
      {
        begin: /\b0b([01]_*)+\b/
      } ]
    };
    SUBST.contains = [ NUMBER ];
    return {
      name: "Swift",
      keywords: SWIFT_KEYWORDS,
      contains: [ STRING, hljs.C_LINE_COMMENT_MODE, BLOCK_COMMENT, OPTIONAL_USING_TYPE, TYPE, NUMBER, {
        className: "function",
        beginKeywords: "func",
        end: /\{/,
        excludeEnd: true,
        contains: [ hljs.inherit(hljs.TITLE_MODE, {
          begin: /[A-Za-z$_][0-9A-Za-z$_]*/
        }), {
          begin: /</,
          end: />/
        }, {
          className: "params",
          begin: /\(/,
          end: /\)/,
          endsParent: true,
          keywords: SWIFT_KEYWORDS,
          contains: [ "self", NUMBER, STRING, hljs.C_BLOCK_COMMENT_MODE, {
            begin: ":"
          } ],
          illegal: /["']/
        } ],
        illegal: /\[|%/
      }, {
        className: "class",
        beginKeywords: "struct protocol class extension enum",
        keywords: SWIFT_KEYWORDS,
        end: "\\{",
        excludeEnd: true,
        contains: [ hljs.inherit(hljs.TITLE_MODE, {
          begin: /[A-Za-z$_][\u00C0-\u02B80-9A-Za-z$_]*/
        }) ]
      }, {
        className: "meta",
        // @attributes
        begin: "(@discardableResult|@warn_unused_result|@exported|@lazy|@noescape|" + "@NSCopying|@NSManaged|@objc|@objcMembers|@convention|@required|" + "@noreturn|@IBAction|@IBDesignable|@IBInspectable|@IBOutlet|" + "@infix|@prefix|@postfix|@autoclosure|@testable|@available|" + "@nonobjc|@NSApplicationMain|@UIApplicationMain|@dynamicMemberLookup|" + "@propertyWrapper|@main)\\b"
      }, {
        beginKeywords: "import",
        end: /$/,
        contains: [ hljs.C_LINE_COMMENT_MODE, BLOCK_COMMENT ],
        relevance: 0
      } ]
    };
  }
  var swift_1 = swift;
  /*
  Language: Tcl
  Description: Tcl is a very simple programming language.
  Author: Radek Liska <radekliska@gmail.com>
  Website: https://www.tcl.tk/about/language.html
  */  function tcl(hljs) {
    return {
      name: "Tcl",
      aliases: [ "tk" ],
      keywords: "after append apply array auto_execok auto_import auto_load auto_mkindex " + "auto_mkindex_old auto_qualify auto_reset bgerror binary break catch cd chan clock " + "close concat continue dde dict encoding eof error eval exec exit expr fblocked " + "fconfigure fcopy file fileevent filename flush for foreach format gets glob global " + "history http if incr info interp join lappend|10 lassign|10 lindex|10 linsert|10 list " + "llength|10 load lrange|10 lrepeat|10 lreplace|10 lreverse|10 lsearch|10 lset|10 lsort|10 " + "mathfunc mathop memory msgcat namespace open package parray pid pkg::create pkg_mkIndex " + "platform platform::shell proc puts pwd read refchan regexp registry regsub|10 rename " + "return safe scan seek set socket source split string subst switch tcl_endOfWord " + "tcl_findLibrary tcl_startOfNextWord tcl_startOfPreviousWord tcl_wordBreakAfter " + "tcl_wordBreakBefore tcltest tclvars tell time tm trace unknown unload unset update " + "uplevel upvar variable vwait while",
      contains: [ hljs.COMMENT(";[ \\t]*#", "$"), hljs.COMMENT("^[ \\t]*#", "$"), {
        beginKeywords: "proc",
        end: "[\\{]",
        excludeEnd: true,
        contains: [ {
          className: "title",
          begin: "[ \\t\\n\\r]+(::)?[a-zA-Z_]((::)?[a-zA-Z0-9_])*",
          end: "[ \\t\\n\\r]",
          endsWithParent: true,
          excludeEnd: true
        } ]
      }, {
        excludeEnd: true,
        variants: [ {
          begin: "\\$(\\{)?(::)?[a-zA-Z_]((::)?[a-zA-Z0-9_])*\\(([a-zA-Z0-9_])*\\)",
          end: "[^a-zA-Z0-9_\\}\\$]"
        }, {
          begin: "\\$(\\{)?(::)?[a-zA-Z_]((::)?[a-zA-Z0-9_])*",
          end: "(\\))?[^a-zA-Z0-9_\\}\\$]"
        } ]
      }, {
        className: "string",
        contains: [ hljs.BACKSLASH_ESCAPE ],
        variants: [ hljs.inherit(hljs.QUOTE_STRING_MODE, {
          illegal: null
        }) ]
      }, {
        className: "number",
        variants: [ hljs.BINARY_NUMBER_MODE, hljs.C_NUMBER_MODE ]
      } ]
    };
  }
  var tcl_1 = tcl;
  const IDENT_RE$2 = "[A-Za-z$_][0-9A-Za-z$_]*";
  const KEYWORDS$3 = [ "as", // for exports
  "in", "of", "if", "for", "while", "finally", "var", "new", "function", "do", "return", "void", "else", "break", "catch", "instanceof", "with", "throw", "case", "default", "try", "switch", "continue", "typeof", "delete", "let", "yield", "const", "class", 
  // JS handles these with a special rule
  // "get",
  // "set",
  "debugger", "async", "await", "static", "import", "from", "export", "extends" ];
  const LITERALS$3 = [ "true", "false", "null", "undefined", "NaN", "Infinity" ];
  const TYPES$3 = [ "Intl", "DataView", "Number", "Math", "Date", "String", "RegExp", "Object", "Function", "Boolean", "Error", "Symbol", "Set", "Map", "WeakSet", "WeakMap", "Proxy", "Reflect", "JSON", "Promise", "Float64Array", "Int16Array", "Int32Array", "Int8Array", "Uint16Array", "Uint32Array", "Float32Array", "Array", "Uint8Array", "Uint8ClampedArray", "ArrayBuffer" ];
  const ERROR_TYPES$3 = [ "EvalError", "InternalError", "RangeError", "ReferenceError", "SyntaxError", "TypeError", "URIError" ];
  const BUILT_IN_GLOBALS$3 = [ "setInterval", "setTimeout", "clearInterval", "clearTimeout", "require", "exports", "eval", "isFinite", "isNaN", "parseFloat", "parseInt", "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent", "escape", "unescape" ];
  const BUILT_IN_VARIABLES$3 = [ "arguments", "this", "super", "console", "window", "document", "localStorage", "module", "global" ];
  const BUILT_INS$3 = [].concat(BUILT_IN_GLOBALS$3, BUILT_IN_VARIABLES$3, TYPES$3, ERROR_TYPES$3);
  /**
   * @param {string} value
   * @returns {RegExp}
   * */
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function source$f(re) {
    if (!re) return null;
    if (typeof re === "string") return re;
    return re.source;
  }
  /**
   * @param {RegExp | string } re
   * @returns {string}
   */  function lookahead$5(re) {
    return concat$e("(?=", re, ")");
  }
  /**
   * @param {...(RegExp | string) } args
   * @returns {string}
   */  function concat$e(...args) {
    const joined = args.map((x => source$f(x))).join("");
    return joined;
  }
  /*
  Language: JavaScript
  Description: JavaScript (JS) is a lightweight, interpreted, or just-in-time compiled programming language with first-class functions.
  Category: common, scripting
  Website: https://developer.mozilla.org/en-US/docs/Web/JavaScript
  */
  /** @type LanguageFn */  function javascript$1(hljs) {
    /**
     * Takes a string like "<Booger" and checks to see
     * if we can find a matching "</Booger" later in the
     * content.
     * @param {RegExpMatchArray} match
     * @param {{after:number}} param1
     */
    const hasClosingTag = (match, {after: after}) => {
      const tag = "</" + match[0].slice(1);
      const pos = match.input.indexOf(tag, after);
      return pos !== -1;
    };
    const IDENT_RE$1 = IDENT_RE$2;
    const FRAGMENT = {
      begin: "<>",
      end: "</>"
    };
    const XML_TAG = {
      begin: /<[A-Za-z0-9\\._:-]+/,
      end: /\/[A-Za-z0-9\\._:-]+>|\/>/,
      /**
       * @param {RegExpMatchArray} match
       * @param {CallbackResponse} response
       */
      isTrulyOpeningTag: (match, response) => {
        const afterMatchIndex = match[0].length + match.index;
        const nextChar = match.input[afterMatchIndex];
        // nested type?
        // HTML should not include another raw `<` inside a tag
        // But a type might: `<Array<Array<number>>`, etc.
                if (nextChar === "<") {
          response.ignoreMatch();
          return;
        }
        // <something>
        // This is now either a tag or a type.
                if (nextChar === ">") {
          // if we cannot find a matching closing tag, then we
          // will ignore it
          if (!hasClosingTag(match, {
            after: afterMatchIndex
          })) {
            response.ignoreMatch();
          }
        }
      }
    };
    const KEYWORDS$1 = {
      $pattern: IDENT_RE$2,
      keyword: KEYWORDS$3.join(" "),
      literal: LITERALS$3.join(" "),
      built_in: BUILT_INS$3.join(" ")
    };
    // https://tc39.es/ecma262/#sec-literals-numeric-literals
        const decimalDigits = "[0-9](_?[0-9])*";
    const frac = `\\.(${decimalDigits})`;
    // DecimalIntegerLiteral, including Annex B NonOctalDecimalIntegerLiteral
    // https://tc39.es/ecma262/#sec-additional-syntax-numeric-literals
        const decimalInteger = `0|[1-9](_?[0-9])*|0[0-7]*[89][0-9]*`;
    const NUMBER = {
      className: "number",
      variants: [ 
      // DecimalLiteral
      {
        begin: `(\\b(${decimalInteger})((${frac})|\\.)?|(${frac}))` + `[eE][+-]?(${decimalDigits})\\b`
      }, {
        begin: `\\b(${decimalInteger})\\b((${frac})\\b|\\.)?|(${frac})\\b`
      }, 
      // DecimalBigIntegerLiteral
      {
        begin: `\\b(0|[1-9](_?[0-9])*)n\\b`
      }, 
      // NonDecimalIntegerLiteral
      {
        begin: "\\b0[xX][0-9a-fA-F](_?[0-9a-fA-F])*n?\\b"
      }, {
        begin: "\\b0[bB][0-1](_?[0-1])*n?\\b"
      }, {
        begin: "\\b0[oO][0-7](_?[0-7])*n?\\b"
      }, 
      // LegacyOctalIntegerLiteral (does not include underscore separators)
      // https://tc39.es/ecma262/#sec-additional-syntax-numeric-literals
      {
        begin: "\\b0[0-7]+n?\\b"
      } ],
      relevance: 0
    };
    const SUBST = {
      className: "subst",
      begin: "\\$\\{",
      end: "\\}",
      keywords: KEYWORDS$1,
      contains: []
    };
    const HTML_TEMPLATE = {
      begin: "html`",
      end: "",
      starts: {
        end: "`",
        returnEnd: false,
        contains: [ hljs.BACKSLASH_ESCAPE, SUBST ],
        subLanguage: "xml"
      }
    };
    const CSS_TEMPLATE = {
      begin: "css`",
      end: "",
      starts: {
        end: "`",
        returnEnd: false,
        contains: [ hljs.BACKSLASH_ESCAPE, SUBST ],
        subLanguage: "css"
      }
    };
    const TEMPLATE_STRING = {
      className: "string",
      begin: "`",
      end: "`",
      contains: [ hljs.BACKSLASH_ESCAPE, SUBST ]
    };
    const JSDOC_COMMENT = hljs.COMMENT("/\\*\\*", "\\*/", {
      relevance: 0,
      contains: [ {
        className: "doctag",
        begin: "@[A-Za-z]+",
        contains: [ {
          className: "type",
          begin: "\\{",
          end: "\\}",
          relevance: 0
        }, {
          className: "variable",
          begin: IDENT_RE$1 + "(?=\\s*(-)|$)",
          endsParent: true,
          relevance: 0
        }, 
        // eat spaces (not newlines) so we can find
        // types or variables
        {
          begin: /(?=[^\n])\s/,
          relevance: 0
        } ]
      } ]
    });
    const COMMENT = {
      className: "comment",
      variants: [ JSDOC_COMMENT, hljs.C_BLOCK_COMMENT_MODE, hljs.C_LINE_COMMENT_MODE ]
    };
    const SUBST_INTERNALS = [ hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, HTML_TEMPLATE, CSS_TEMPLATE, TEMPLATE_STRING, NUMBER, hljs.REGEXP_MODE ];
    SUBST.contains = SUBST_INTERNALS.concat({
      // we need to pair up {} inside our subst to prevent
      // it from ending too early by matching another }
      begin: /\{/,
      end: /\}/,
      keywords: KEYWORDS$1,
      contains: [ "self" ].concat(SUBST_INTERNALS)
    });
    const SUBST_AND_COMMENTS = [].concat(COMMENT, SUBST.contains);
    const PARAMS_CONTAINS = SUBST_AND_COMMENTS.concat([ 
    // eat recursive parens in sub expressions
    {
      begin: /\(/,
      end: /\)/,
      keywords: KEYWORDS$1,
      contains: [ "self" ].concat(SUBST_AND_COMMENTS)
    } ]);
    const PARAMS = {
      className: "params",
      begin: /\(/,
      end: /\)/,
      excludeBegin: true,
      excludeEnd: true,
      keywords: KEYWORDS$1,
      contains: PARAMS_CONTAINS
    };
    return {
      name: "Javascript",
      aliases: [ "js", "jsx", "mjs", "cjs" ],
      keywords: KEYWORDS$1,
      // this will be extended by TypeScript
      exports: {
        PARAMS_CONTAINS: PARAMS_CONTAINS
      },
      illegal: /#(?![$_A-z])/,
      contains: [ hljs.SHEBANG({
        label: "shebang",
        binary: "node",
        relevance: 5
      }), {
        label: "use_strict",
        className: "meta",
        relevance: 10,
        begin: /^\s*['"]use (strict|asm)['"]/
      }, hljs.APOS_STRING_MODE, hljs.QUOTE_STRING_MODE, HTML_TEMPLATE, CSS_TEMPLATE, TEMPLATE_STRING, COMMENT, NUMBER, {
        // object attr container
        begin: concat$e(/[{,\n]\s*/, 
        // we need to look ahead to make sure that we actually have an
        // attribute coming up so we don't steal a comma from a potential
        // "value" container
        // NOTE: this might not work how you think.  We don't actually always
        // enter this mode and stay.  Instead it might merely match `,
        // <comments up next>` and then immediately end after the , because it
        // fails to find any actual attrs. But this still does the job because
        // it prevents the value contain rule from grabbing this instead and
        // prevening this rule from firing when we actually DO have keys.
        lookahead$5(concat$e(
        // we also need to allow for multiple possible comments inbetween
        // the first key:value pairing
        /(((\/\/.*$)|(\/\*(\*[^/]|[^*])*\*\/))\s*)*/, IDENT_RE$1 + "\\s*:"))),
        relevance: 0,
        contains: [ {
          className: "attr",
          begin: IDENT_RE$1 + lookahead$5("\\s*:"),
          relevance: 0
        } ]
      }, {
        // "value" container
        begin: "(" + hljs.RE_STARTERS_RE + "|\\b(case|return|throw)\\b)\\s*",
        keywords: "return throw case",
        contains: [ COMMENT, hljs.REGEXP_MODE, {
          className: "function",
          // we have to count the parens to make sure we actually have the
          // correct bounding ( ) before the =>.  There could be any number of
          // sub-expressions inside also surrounded by parens.
          begin: "(\\(" + "[^()]*(\\(" + "[^()]*(\\(" + "[^()]*" + "\\)[^()]*)*" + "\\)[^()]*)*" + "\\)|" + hljs.UNDERSCORE_IDENT_RE + ")\\s*=>",
          returnBegin: true,
          end: "\\s*=>",
          contains: [ {
            className: "params",
            variants: [ {
              begin: hljs.UNDERSCORE_IDENT_RE,
              relevance: 0
            }, {
              className: null,
              begin: /\(\s*\)/,
              skip: true
            }, {
              begin: /\(/,
              end: /\)/,
              excludeBegin: true,
              excludeEnd: true,
              keywords: KEYWORDS$1,
              contains: PARAMS_CONTAINS
            } ]
          } ]
        }, {
          // could be a comma delimited list of params to a function call
          begin: /,/,
          relevance: 0
        }, {
          className: "",
          begin: /\s/,
          end: /\s*/,
          skip: true
        }, {
          // JSX
          variants: [ {
            begin: FRAGMENT.begin,
            end: FRAGMENT.end
          }, {
            begin: XML_TAG.begin,
            // we carefully check the opening tag to see if it truly
            // is a tag and not a false positive
            "on:begin": XML_TAG.isTrulyOpeningTag,
            end: XML_TAG.end
          } ],
          subLanguage: "xml",
          contains: [ {
            begin: XML_TAG.begin,
            end: XML_TAG.end,
            skip: true,
            contains: [ "self" ]
          } ]
        } ],
        relevance: 0
      }, {
        className: "function",
        beginKeywords: "function",
        end: /[{;]/,
        excludeEnd: true,
        keywords: KEYWORDS$1,
        contains: [ "self", hljs.inherit(hljs.TITLE_MODE, {
          begin: IDENT_RE$1
        }), PARAMS ],
        illegal: /%/
      }, {
        // prevent this from getting swallowed up by function
        // since they appear "function like"
        beginKeywords: "while if switch catch for"
      }, {
        className: "function",
        // we have to count the parens to make sure we actually have the correct
        // bounding ( ).  There could be any number of sub-expressions inside
        // also surrounded by parens.
        begin: hljs.UNDERSCORE_IDENT_RE + "\\(" + // first parens
        "[^()]*(\\(" + "[^()]*(\\(" + "[^()]*" + "\\)[^()]*)*" + "\\)[^()]*)*" + "\\)\\s*\\{",
        // end parens
        returnBegin: true,
        contains: [ PARAMS, hljs.inherit(hljs.TITLE_MODE, {
          begin: IDENT_RE$1
        }) ]
      }, 
      // hack: prevents detection of keywords in some circumstances
      // .keyword()
      // $keyword = x
      {
        variants: [ {
          begin: "\\." + IDENT_RE$1
        }, {
          begin: "\\$" + IDENT_RE$1
        } ],
        relevance: 0
      }, {
        // ES6 class
        className: "class",
        beginKeywords: "class",
        end: /[{;=]/,
        excludeEnd: true,
        illegal: /[:"[\]]/,
        contains: [ {
          beginKeywords: "extends"
        }, hljs.UNDERSCORE_TITLE_MODE ]
      }, {
        begin: /\b(?=constructor)/,
        end: /[{;]/,
        excludeEnd: true,
        contains: [ hljs.inherit(hljs.TITLE_MODE, {
          begin: IDENT_RE$1
        }), "self", PARAMS ]
      }, {
        begin: "(get|set)\\s+(?=" + IDENT_RE$1 + "\\()",
        end: /\{/,
        keywords: "get set",
        contains: [ hljs.inherit(hljs.TITLE_MODE, {
          begin: IDENT_RE$1
        }), {
          begin: /\(\)/
        }, // eat to avoid empty params
        PARAMS ]
      }, {
        begin: /\$[(.]/
      } ]
    };
  }
  /*
  Language: TypeScript
  Author: Panu Horsmalahti <panu.horsmalahti@iki.fi>
  Contributors: Ike Ku <dempfi@yahoo.com>
  Description: TypeScript is a strict superset of JavaScript
  Website: https://www.typescriptlang.org
  Category: common, scripting
  */
  /** @type LanguageFn */  function typescript(hljs) {
    const IDENT_RE$1 = IDENT_RE$2;
    const NAMESPACE = {
      beginKeywords: "namespace",
      end: /\{/,
      excludeEnd: true
    };
    const INTERFACE = {
      beginKeywords: "interface",
      end: /\{/,
      excludeEnd: true,
      keywords: "interface extends"
    };
    const USE_STRICT = {
      className: "meta",
      relevance: 10,
      begin: /^\s*['"]use strict['"]/
    };
    const TYPES = [ "any", "void", "number", "boolean", "string", "object", "never", "enum" ];
    const TS_SPECIFIC_KEYWORDS = [ "type", "namespace", "typedef", "interface", "public", "private", "protected", "implements", "declare", "abstract", "readonly" ];
    const KEYWORDS$1 = {
      $pattern: IDENT_RE$2,
      keyword: KEYWORDS$3.concat(TS_SPECIFIC_KEYWORDS).join(" "),
      literal: LITERALS$3.join(" "),
      built_in: BUILT_INS$3.concat(TYPES).join(" ")
    };
    const DECORATOR = {
      className: "meta",
      begin: "@" + IDENT_RE$1
    };
    const swapMode = (mode, label, replacement) => {
      const indx = mode.contains.findIndex((m => m.label === label));
      if (indx === -1) {
        throw new Error("can not find mode to replace");
      }
      mode.contains.splice(indx, 1, replacement);
    };
    const tsLanguage = javascript$1(hljs);
    // this should update anywhere keywords is used since
    // it will be the same actual JS object
        Object.assign(tsLanguage.keywords, KEYWORDS$1);
    tsLanguage.exports.PARAMS_CONTAINS.push(DECORATOR);
    tsLanguage.contains = tsLanguage.contains.concat([ DECORATOR, NAMESPACE, INTERFACE ]);
    // TS gets a simpler shebang rule than JS
        swapMode(tsLanguage, "shebang", hljs.SHEBANG());
    // JS use strict rule purposely excludes `asm` which makes no sense
        swapMode(tsLanguage, "use_strict", USE_STRICT);
    const functionDeclaration = tsLanguage.contains.find((m => m.className === "function"));
    functionDeclaration.relevance = 0;
 // () => {} is more typical in TypeScript
        Object.assign(tsLanguage, {
      name: "TypeScript",
      aliases: [ "ts" ]
    });
    return tsLanguage;
  }
  var typescript_1 = typescript;
  /*
  Language: Verilog
  Author: Jon Evans <jon@craftyjon.com>
  Contributors: Boone Severson <boone.severson@gmail.com>
  Description: Verilog is a hardware description language used in electronic design automation to describe digital and mixed-signal systems. This highlighter supports Verilog and SystemVerilog through IEEE 1800-2012.
  Website: http://www.verilog.com
  */  function verilog(hljs) {
    const SV_KEYWORDS = {
      $pattern: /[\w\$]+/,
      keyword: "accept_on alias always always_comb always_ff always_latch and assert assign " + "assume automatic before begin bind bins binsof bit break buf|0 bufif0 bufif1 " + "byte case casex casez cell chandle checker class clocking cmos config const " + "constraint context continue cover covergroup coverpoint cross deassign default " + "defparam design disable dist do edge else end endcase endchecker endclass " + "endclocking endconfig endfunction endgenerate endgroup endinterface endmodule " + "endpackage endprimitive endprogram endproperty endspecify endsequence endtable " + "endtask enum event eventually expect export extends extern final first_match for " + "force foreach forever fork forkjoin function generate|5 genvar global highz0 highz1 " + "if iff ifnone ignore_bins illegal_bins implements implies import incdir include " + "initial inout input inside instance int integer interconnect interface intersect " + "join join_any join_none large let liblist library local localparam logic longint " + "macromodule matches medium modport module nand negedge nettype new nexttime nmos " + "nor noshowcancelled not notif0 notif1 or output package packed parameter pmos " + "posedge primitive priority program property protected pull0 pull1 pulldown pullup " + "pulsestyle_ondetect pulsestyle_onevent pure rand randc randcase randsequence rcmos " + "real realtime ref reg reject_on release repeat restrict return rnmos rpmos rtran " + "rtranif0 rtranif1 s_always s_eventually s_nexttime s_until s_until_with scalared " + "sequence shortint shortreal showcancelled signed small soft solve specify specparam " + "static string strong strong0 strong1 struct super supply0 supply1 sync_accept_on " + "sync_reject_on table tagged task this throughout time timeprecision timeunit tran " + "tranif0 tranif1 tri tri0 tri1 triand trior trireg type typedef union unique unique0 " + "unsigned until until_with untyped use uwire var vectored virtual void wait wait_order " + "wand weak weak0 weak1 while wildcard wire with within wor xnor xor",
      literal: "null",
      built_in: "$finish $stop $exit $fatal $error $warning $info $realtime $time $printtimescale " + "$bitstoreal $bitstoshortreal $itor $signed $cast $bits $stime $timeformat " + "$realtobits $shortrealtobits $rtoi $unsigned $asserton $assertkill $assertpasson " + "$assertfailon $assertnonvacuouson $assertoff $assertcontrol $assertpassoff " + "$assertfailoff $assertvacuousoff $isunbounded $sampled $fell $changed $past_gclk " + "$fell_gclk $changed_gclk $rising_gclk $steady_gclk $coverage_control " + "$coverage_get $coverage_save $set_coverage_db_name $rose $stable $past " + "$rose_gclk $stable_gclk $future_gclk $falling_gclk $changing_gclk $display " + "$coverage_get_max $coverage_merge $get_coverage $load_coverage_db $typename " + "$unpacked_dimensions $left $low $increment $clog2 $ln $log10 $exp $sqrt $pow " + "$floor $ceil $sin $cos $tan $countbits $onehot $isunknown $fatal $warning " + "$dimensions $right $high $size $asin $acos $atan $atan2 $hypot $sinh $cosh " + "$tanh $asinh $acosh $atanh $countones $onehot0 $error $info $random " + "$dist_chi_square $dist_erlang $dist_exponential $dist_normal $dist_poisson " + "$dist_t $dist_uniform $q_initialize $q_remove $q_exam $async$and$array " + "$async$nand$array $async$or$array $async$nor$array $sync$and$array " + "$sync$nand$array $sync$or$array $sync$nor$array $q_add $q_full $psprintf " + "$async$and$plane $async$nand$plane $async$or$plane $async$nor$plane " + "$sync$and$plane $sync$nand$plane $sync$or$plane $sync$nor$plane $system " + "$display $displayb $displayh $displayo $strobe $strobeb $strobeh $strobeo " + "$write $readmemb $readmemh $writememh $value$plusargs " + "$dumpvars $dumpon $dumplimit $dumpports $dumpportson $dumpportslimit " + "$writeb $writeh $writeo $monitor $monitorb $monitorh $monitoro $writememb " + "$dumpfile $dumpoff $dumpall $dumpflush $dumpportsoff $dumpportsall " + "$dumpportsflush $fclose $fdisplay $fdisplayb $fdisplayh $fdisplayo " + "$fstrobe $fstrobeb $fstrobeh $fstrobeo $swrite $swriteb $swriteh " + "$swriteo $fscanf $fread $fseek $fflush $feof $fopen $fwrite $fwriteb " + "$fwriteh $fwriteo $fmonitor $fmonitorb $fmonitorh $fmonitoro $sformat " + "$sformatf $fgetc $ungetc $fgets $sscanf $rewind $ftell $ferror"
    };
    return {
      name: "Verilog",
      aliases: [ "v", "sv", "svh" ],
      case_insensitive: false,
      keywords: SV_KEYWORDS,
      contains: [ hljs.C_BLOCK_COMMENT_MODE, hljs.C_LINE_COMMENT_MODE, hljs.QUOTE_STRING_MODE, {
        className: "number",
        contains: [ hljs.BACKSLASH_ESCAPE ],
        variants: [ {
          begin: "\\b((\\d+'(b|h|o|d|B|H|O|D))[0-9xzXZa-fA-F_]+)"
        }, {
          begin: "\\B(('(b|h|o|d|B|H|O|D))[0-9xzXZa-fA-F_]+)"
        }, {
          begin: "\\b([0-9_])+",
          relevance: 0
        } ]
      }, 
      /* parameters to instances */
      {
        className: "variable",
        variants: [ {
          begin: "#\\((?!parameter).+\\)"
        }, {
          begin: "\\.\\w+",
          relevance: 0
        } ]
      }, {
        className: "meta",
        begin: "`",
        end: "$",
        keywords: {
          "meta-keyword": "define __FILE__ " + "__LINE__ begin_keywords celldefine default_nettype define " + "else elsif end_keywords endcelldefine endif ifdef ifndef " + "include line nounconnected_drive pragma resetall timescale " + "unconnected_drive undef undefineall"
        },
        relevance: 0
      } ]
    };
  }
  var verilog_1 = verilog;
  /*
  Language: VHDL
  Author: Igor Kalnitsky <igor@kalnitsky.org>
  Contributors: Daniel C.K. Kho <daniel.kho@tauhop.com>, Guillaume Savaton <guillaume.savaton@eseo.fr>
  Description: VHDL is a hardware description language used in electronic design automation to describe digital and mixed-signal systems.
  Website: https://en.wikipedia.org/wiki/VHDL
  */  function vhdl(hljs) {
    // Regular expression for VHDL numeric literals.
    // Decimal literal:
    const INTEGER_RE = "\\d(_|\\d)*";
    const EXPONENT_RE = "[eE][-+]?" + INTEGER_RE;
    const DECIMAL_LITERAL_RE = INTEGER_RE + "(\\." + INTEGER_RE + ")?" + "(" + EXPONENT_RE + ")?";
    // Based literal:
        const BASED_INTEGER_RE = "\\w+";
    const BASED_LITERAL_RE = INTEGER_RE + "#" + BASED_INTEGER_RE + "(\\." + BASED_INTEGER_RE + ")?" + "#" + "(" + EXPONENT_RE + ")?";
    const NUMBER_RE = "\\b(" + BASED_LITERAL_RE + "|" + DECIMAL_LITERAL_RE + ")";
    return {
      name: "VHDL",
      case_insensitive: true,
      keywords: {
        keyword: "abs access after alias all and architecture array assert assume assume_guarantee attribute " + "begin block body buffer bus case component configuration constant context cover disconnect " + "downto default else elsif end entity exit fairness file for force function generate " + "generic group guarded if impure in inertial inout is label library linkage literal " + "loop map mod nand new next nor not null of on open or others out package parameter port " + "postponed procedure process property protected pure range record register reject " + "release rem report restrict restrict_guarantee return rol ror select sequence " + "severity shared signal sla sll sra srl strong subtype then to transport type " + "unaffected units until use variable view vmode vprop vunit wait when while with xnor xor",
        built_in: "boolean bit character " + "integer time delay_length natural positive " + "string bit_vector file_open_kind file_open_status " + "std_logic std_logic_vector unsigned signed boolean_vector integer_vector " + "std_ulogic std_ulogic_vector unresolved_unsigned u_unsigned unresolved_signed u_signed " + "real_vector time_vector",
        literal: "false true note warning error failure " + // severity_level
        "line text side width"
      },
      illegal: /\{/,
      contains: [ hljs.C_BLOCK_COMMENT_MODE, // VHDL-2008 block commenting.
      hljs.COMMENT("--", "$"), hljs.QUOTE_STRING_MODE, {
        className: "number",
        begin: NUMBER_RE,
        relevance: 0
      }, {
        className: "string",
        begin: "'(U|X|0|1|Z|W|L|H|-)'",
        contains: [ hljs.BACKSLASH_ESCAPE ]
      }, {
        className: "symbol",
        begin: "'[A-Za-z](_?[A-Za-z0-9])*",
        contains: [ hljs.BACKSLASH_ESCAPE ]
      } ]
    };
  }
  var vhdl_1 = vhdl;
  /*
  Language: YAML
  Description: Yet Another Markdown Language
  Author: Stefan Wienert <stwienert@gmail.com>
  Contributors: Carl Baxter <carl@cbax.tech>
  Requires: ruby.js
  Website: https://yaml.org
  Category: common, config
  */  function yaml(hljs) {
    var LITERALS = "true false yes no null";
    // YAML spec allows non-reserved URI characters in tags.
        var URI_CHARACTERS = "[\\w#;/?:@&=+$,.~*'()[\\]]+";
    // Define keys as starting with a word character
    // ...containing word chars, spaces, colons, forward-slashes, hyphens and periods
    // ...and ending with a colon followed immediately by a space, tab or newline.
    // The YAML spec allows for much more than this, but this covers most use-cases.
        var KEY = {
      className: "attr",
      variants: [ {
        begin: "\\w[\\w :\\/.-]*:(?=[ \t]|$)"
      }, {
        begin: '"\\w[\\w :\\/.-]*":(?=[ \t]|$)'
      }, // double quoted keys
      {
        begin: "'\\w[\\w :\\/.-]*':(?=[ \t]|$)"
      } ]
    };
    var TEMPLATE_VARIABLES = {
      className: "template-variable",
      variants: [ {
        begin: /\{\{/,
        end: /\}\}/
      }, // jinja templates Ansible
      {
        begin: /%\{/,
        end: /\}/
      } ]
    };
    var STRING = {
      className: "string",
      relevance: 0,
      variants: [ {
        begin: /'/,
        end: /'/
      }, {
        begin: /"/,
        end: /"/
      }, {
        begin: /\S+/
      } ],
      contains: [ hljs.BACKSLASH_ESCAPE, TEMPLATE_VARIABLES ]
    };
    // Strings inside of value containers (objects) can't contain braces,
    // brackets, or commas
        var CONTAINER_STRING = hljs.inherit(STRING, {
      variants: [ {
        begin: /'/,
        end: /'/
      }, {
        begin: /"/,
        end: /"/
      }, {
        begin: /[^\s,{}[\]]+/
      } ]
    });
    var DATE_RE = "[0-9]{4}(-[0-9][0-9]){0,2}";
    var TIME_RE = "([Tt \\t][0-9][0-9]?(:[0-9][0-9]){2})?";
    var FRACTION_RE = "(\\.[0-9]*)?";
    var ZONE_RE = "([ \\t])*(Z|[-+][0-9][0-9]?(:[0-9][0-9])?)?";
    var TIMESTAMP = {
      className: "number",
      begin: "\\b" + DATE_RE + TIME_RE + FRACTION_RE + ZONE_RE + "\\b"
    };
    var VALUE_CONTAINER = {
      end: ",",
      endsWithParent: true,
      excludeEnd: true,
      contains: [],
      keywords: LITERALS,
      relevance: 0
    };
    var OBJECT = {
      begin: /\{/,
      end: /\}/,
      contains: [ VALUE_CONTAINER ],
      illegal: "\\n",
      relevance: 0
    };
    var ARRAY = {
      begin: "\\[",
      end: "\\]",
      contains: [ VALUE_CONTAINER ],
      illegal: "\\n",
      relevance: 0
    };
    var MODES = [ KEY, {
      className: "meta",
      begin: "^---\\s*$",
      relevance: 10
    }, {
      // multi line string
      // Blocks start with a | or > followed by a newline
      // Indentation of subsequent lines must be the same to
      // be considered part of the block
      className: "string",
      begin: "[\\|>]([1-9]?[+-])?[ ]*\\n( +)[^ ][^\\n]*\\n(\\2[^\\n]+\\n?)*"
    }, {
      // Ruby/Rails erb
      begin: "<%[%=-]?",
      end: "[%-]?%>",
      subLanguage: "ruby",
      excludeBegin: true,
      excludeEnd: true,
      relevance: 0
    }, {
      // named tags
      className: "type",
      begin: "!\\w+!" + URI_CHARACTERS
    }, 
    // https://yaml.org/spec/1.2/spec.html#id2784064
    {
      // verbatim tags
      className: "type",
      begin: "!<" + URI_CHARACTERS + ">"
    }, {
      // primary tags
      className: "type",
      begin: "!" + URI_CHARACTERS
    }, {
      // secondary tags
      className: "type",
      begin: "!!" + URI_CHARACTERS
    }, {
      // fragment id &ref
      className: "meta",
      begin: "&" + hljs.UNDERSCORE_IDENT_RE + "$"
    }, {
      // fragment reference *ref
      className: "meta",
      begin: "\\*" + hljs.UNDERSCORE_IDENT_RE + "$"
    }, {
      // array listing
      className: "bullet",
      // TODO: remove |$ hack when we have proper look-ahead support
      begin: "-(?=[ ]|$)",
      relevance: 0
    }, hljs.HASH_COMMENT_MODE, {
      beginKeywords: LITERALS,
      keywords: {
        literal: LITERALS
      }
    }, TIMESTAMP, 
    // numbers are any valid C-style number that
    // sit isolated from other words
    {
      className: "number",
      begin: hljs.C_NUMBER_RE + "\\b",
      relevance: 0
    }, OBJECT, ARRAY, STRING ];
    var VALUE_MODES = [ ...MODES ];
    VALUE_MODES.pop();
    VALUE_MODES.push(CONTAINER_STRING);
    VALUE_CONTAINER.contains = VALUE_MODES;
    return {
      name: "YAML",
      case_insensitive: true,
      aliases: [ "yml", "YAML" ],
      contains: MODES
    };
  }
  var yaml_1 = yaml;
  // Enclose abbreviations in <abbr> tags
    var markdownItAbbr = function sub_plugin(md) {
    var escapeRE = md.utils.escapeRE, arrayReplaceAt = md.utils.arrayReplaceAt;
    // ASCII characters in Cc, Sc, Sm, Sk categories we should terminate on;
    // you can check character classes here:
    // http://www.unicode.org/Public/UNIDATA/UnicodeData.txt
        var OTHER_CHARS = " \r\n$+<=>^`|~";
    var UNICODE_PUNCT_RE = md.utils.lib.ucmicro.P.source;
    var UNICODE_SPACE_RE = md.utils.lib.ucmicro.Z.source;
    function abbr_def(state, startLine, endLine, silent) {
      var label, title, ch, labelStart, labelEnd, pos = state.bMarks[startLine] + state.tShift[startLine], max = state.eMarks[startLine];
      if (pos + 2 >= max) {
        return false;
      }
      if (state.src.charCodeAt(pos++) !== 42 /* * */) {
        return false;
      }
      if (state.src.charCodeAt(pos++) !== 91 /* [ */) {
        return false;
      }
      labelStart = pos;
      for (;pos < max; pos++) {
        ch = state.src.charCodeAt(pos);
        if (ch === 91 /* [ */) {
          return false;
        } else if (ch === 93 /* ] */) {
          labelEnd = pos;
          break;
        } else if (ch === 92 /* \ */) {
          pos++;
        }
      }
      if (labelEnd < 0 || state.src.charCodeAt(labelEnd + 1) !== 58 /* : */) {
        return false;
      }
      if (silent) {
        return true;
      }
      label = state.src.slice(labelStart, labelEnd).replace(/\\(.)/g, "$1");
      title = state.src.slice(labelEnd + 2, max).trim();
      if (label.length === 0) {
        return false;
      }
      if (title.length === 0) {
        return false;
      }
      if (!state.env.abbreviations) {
        state.env.abbreviations = {};
      }
      // prepend ':' to avoid conflict with Object.prototype members
            if (typeof state.env.abbreviations[":" + label] === "undefined") {
        state.env.abbreviations[":" + label] = title;
      }
      state.line = startLine + 1;
      return true;
    }
    function abbr_replace(state) {
      var i, j, l, tokens, token, text, nodes, pos, reg, m, regText, regSimple, currentToken, blockTokens = state.tokens;
      if (!state.env.abbreviations) {
        return;
      }
      regSimple = new RegExp("(?:" + Object.keys(state.env.abbreviations).map((function(x) {
        return x.substr(1);
      })).sort((function(a, b) {
        return b.length - a.length;
      })).map(escapeRE).join("|") + ")");
      regText = "(^|" + UNICODE_PUNCT_RE + "|" + UNICODE_SPACE_RE + "|[" + OTHER_CHARS.split("").map(escapeRE).join("") + "])" + "(" + Object.keys(state.env.abbreviations).map((function(x) {
        return x.substr(1);
      })).sort((function(a, b) {
        return b.length - a.length;
      })).map(escapeRE).join("|") + ")" + "($|" + UNICODE_PUNCT_RE + "|" + UNICODE_SPACE_RE + "|[" + OTHER_CHARS.split("").map(escapeRE).join("") + "])";
      reg = new RegExp(regText, "g");
      for (j = 0, l = blockTokens.length; j < l; j++) {
        if (blockTokens[j].type !== "inline") {
          continue;
        }
        tokens = blockTokens[j].children;
        // We scan from the end, to keep position when new tags added.
                for (i = tokens.length - 1; i >= 0; i--) {
          currentToken = tokens[i];
          if (currentToken.type !== "text") {
            continue;
          }
          pos = 0;
          text = currentToken.content;
          reg.lastIndex = 0;
          nodes = [];
          // fast regexp run to determine whether there are any abbreviated words
          // in the current token
                    if (!regSimple.test(text)) {
            continue;
          }
          while (m = reg.exec(text)) {
            if (m.index > 0 || m[1].length > 0) {
              token = new state.Token("text", "", 0);
              token.content = text.slice(pos, m.index + m[1].length);
              nodes.push(token);
            }
            token = new state.Token("abbr_open", "abbr", 1);
            token.attrs = [ [ "title", state.env.abbreviations[":" + m[2]] ] ];
            nodes.push(token);
            token = new state.Token("text", "", 0);
            token.content = m[2];
            nodes.push(token);
            token = new state.Token("abbr_close", "abbr", -1);
            nodes.push(token);
            reg.lastIndex -= m[3].length;
            pos = reg.lastIndex;
          }
          if (!nodes.length) {
            continue;
          }
          if (pos < text.length) {
            token = new state.Token("text", "", 0);
            token.content = text.slice(pos);
            nodes.push(token);
          }
          // replace current node
                    blockTokens[j].children = tokens = arrayReplaceAt(tokens, i, nodes);
        }
      }
    }
    md.block.ruler.before("reference", "abbr_def", abbr_def, {
      alt: [ "paragraph", "reference" ]
    });
    md.core.ruler.after("linkify", "abbr_replace", abbr_replace);
  };
  // Process block-level custom containers
    var markdownItContainer = function container_plugin(md, name, options) {
    // Second param may be useful if you decide
    // to increase minimal allowed marker length
    function validateDefault(params /*, markup*/) {
      return params.trim().split(" ", 2)[0] === name;
    }
    function renderDefault(tokens, idx, _options, env, slf) {
      // add a class to the opening tag
      if (tokens[idx].nesting === 1) {
        tokens[idx].attrJoin("class", name);
      }
      return slf.renderToken(tokens, idx, _options, env, slf);
    }
    options = options || {};
    var min_markers = 3, marker_str = options.marker || ":", marker_char = marker_str.charCodeAt(0), marker_len = marker_str.length, validate = options.validate || validateDefault, render = options.render || renderDefault;
    function container(state, startLine, endLine, silent) {
      var pos, nextLine, marker_count, markup, params, token, old_parent, old_line_max, auto_closed = false, start = state.bMarks[startLine] + state.tShift[startLine], max = state.eMarks[startLine];
      // Check out the first character quickly,
      // this should filter out most of non-containers
      
            if (marker_char !== state.src.charCodeAt(start)) {
        return false;
      }
      // Check out the rest of the marker string
      
            for (pos = start + 1; pos <= max; pos++) {
        if (marker_str[(pos - start) % marker_len] !== state.src[pos]) {
          break;
        }
      }
      marker_count = Math.floor((pos - start) / marker_len);
      if (marker_count < min_markers) {
        return false;
      }
      pos -= (pos - start) % marker_len;
      markup = state.src.slice(start, pos);
      params = state.src.slice(pos, max);
      if (!validate(params, markup)) {
        return false;
      }
      // Since start is found, we can report success here in validation mode
      
            if (silent) {
        return true;
      }
      // Search for the end of the block
      
            nextLine = startLine;
      for (;;) {
        nextLine++;
        if (nextLine >= endLine) {
          // unclosed block should be autoclosed by end of document.
          // also block seems to be autoclosed by end of parent
          break;
        }
        start = state.bMarks[nextLine] + state.tShift[nextLine];
        max = state.eMarks[nextLine];
        if (start < max && state.sCount[nextLine] < state.blkIndent) {
          // non-empty line with negative indent should stop the list:
          // - ```
          //  test
          break;
        }
        if (marker_char !== state.src.charCodeAt(start)) {
          continue;
        }
        if (state.sCount[nextLine] - state.blkIndent >= 4) {
          // closing fence should be indented less than 4 spaces
          continue;
        }
        for (pos = start + 1; pos <= max; pos++) {
          if (marker_str[(pos - start) % marker_len] !== state.src[pos]) {
            break;
          }
        }
        // closing code fence must be at least as long as the opening one
                if (Math.floor((pos - start) / marker_len) < marker_count) {
          continue;
        }
        // make sure tail has spaces only
                pos -= (pos - start) % marker_len;
        pos = state.skipSpaces(pos);
        if (pos < max) {
          continue;
        }
        // found!
                auto_closed = true;
        break;
      }
      old_parent = state.parentType;
      old_line_max = state.lineMax;
      state.parentType = "container";
      // this will prevent lazy continuations from ever going past our end marker
            state.lineMax = nextLine;
      token = state.push("container_" + name + "_open", "div", 1);
      token.markup = markup;
      token.block = true;
      token.info = params;
      token.map = [ startLine, nextLine ];
      state.md.block.tokenize(state, startLine + 1, nextLine);
      token = state.push("container_" + name + "_close", "div", -1);
      token.markup = state.src.slice(start, pos);
      token.block = true;
      state.parentType = old_parent;
      state.lineMax = old_line_max;
      state.line = nextLine + (auto_closed ? 1 : 0);
      return true;
    }
    md.block.ruler.before("fence", "container_" + name, container, {
      alt: [ "paragraph", "reference", "blockquote", "list" ]
    });
    md.renderer.rules["container_" + name + "_open"] = render;
    md.renderer.rules["container_" + name + "_close"] = render;
  };
  // Process definition lists
    var markdownItDeflist = function deflist_plugin(md) {
    var isSpace = md.utils.isSpace;
    // Search `[:~][\n ]`, returns next pos after marker on success
    // or -1 on fail.
        function skipMarker(state, line) {
      var pos, marker, start = state.bMarks[line] + state.tShift[line], max = state.eMarks[line];
      if (start >= max) {
        return -1;
      }
      // Check bullet
            marker = state.src.charCodeAt(start++);
      if (marker !== 126 /* ~ */ && marker !== 58 /* : */) {
        return -1;
      }
      pos = state.skipSpaces(start);
      // require space after ":"
            if (start === pos) {
        return -1;
      }
      // no empty definitions, e.g. "  : "
            if (pos >= max) {
        return -1;
      }
      return start;
    }
    function markTightParagraphs(state, idx) {
      var i, l, level = state.level + 2;
      for (i = idx + 2, l = state.tokens.length - 2; i < l; i++) {
        if (state.tokens[i].level === level && state.tokens[i].type === "paragraph_open") {
          state.tokens[i + 2].hidden = true;
          state.tokens[i].hidden = true;
          i += 2;
        }
      }
    }
    function deflist(state, startLine, endLine, silent) {
      var ch, contentStart, ddLine, dtLine, itemLines, listLines, listTokIdx, max, nextLine, offset, oldDDIndent, oldIndent, oldParentType, oldSCount, oldTShift, oldTight, pos, prevEmptyEnd, tight, token;
      if (silent) {
        // quirk: validation mode validates a dd block only, not a whole deflist
        if (state.ddIndent < 0) {
          return false;
        }
        return skipMarker(state, startLine) >= 0;
      }
      nextLine = startLine + 1;
      if (nextLine >= endLine) {
        return false;
      }
      if (state.isEmpty(nextLine)) {
        nextLine++;
        if (nextLine >= endLine) {
          return false;
        }
      }
      if (state.sCount[nextLine] < state.blkIndent) {
        return false;
      }
      contentStart = skipMarker(state, nextLine);
      if (contentStart < 0) {
        return false;
      }
      // Start list
            listTokIdx = state.tokens.length;
      tight = true;
      token = state.push("dl_open", "dl", 1);
      token.map = listLines = [ startLine, 0 ];
      
      // Iterate list items
      
            dtLine = startLine;
      ddLine = nextLine;
      // One definition list can contain multiple DTs,
      // and one DT can be followed by multiple DDs.
      
      // Thus, there is two loops here, and label is
      // needed to break out of the second one
      
      /*eslint no-labels:0,block-scoped-var:0*/      OUTER: for (;;) {
        prevEmptyEnd = false;
        token = state.push("dt_open", "dt", 1);
        token.map = [ dtLine, dtLine ];
        token = state.push("inline", "", 0);
        token.map = [ dtLine, dtLine ];
        token.content = state.getLines(dtLine, dtLine + 1, state.blkIndent, false).trim();
        token.children = [];
        token = state.push("dt_close", "dt", -1);
        for (;;) {
          token = state.push("dd_open", "dd", 1);
          token.map = itemLines = [ nextLine, 0 ];
          pos = contentStart;
          max = state.eMarks[ddLine];
          offset = state.sCount[ddLine] + contentStart - (state.bMarks[ddLine] + state.tShift[ddLine]);
          while (pos < max) {
            ch = state.src.charCodeAt(pos);
            if (isSpace(ch)) {
              if (ch === 9) {
                offset += 4 - offset % 4;
              } else {
                offset++;
              }
            } else {
              break;
            }
            pos++;
          }
          contentStart = pos;
          oldTight = state.tight;
          oldDDIndent = state.ddIndent;
          oldIndent = state.blkIndent;
          oldTShift = state.tShift[ddLine];
          oldSCount = state.sCount[ddLine];
          oldParentType = state.parentType;
          state.blkIndent = state.ddIndent = state.sCount[ddLine] + 2;
          state.tShift[ddLine] = contentStart - state.bMarks[ddLine];
          state.sCount[ddLine] = offset;
          state.tight = true;
          state.parentType = "deflist";
          state.md.block.tokenize(state, ddLine, endLine, true);
          // If any of list item is tight, mark list as tight
                    if (!state.tight || prevEmptyEnd) {
            tight = false;
          }
          // Item become loose if finish with empty line,
          // but we should filter last element, because it means list finish
                    prevEmptyEnd = state.line - ddLine > 1 && state.isEmpty(state.line - 1);
          state.tShift[ddLine] = oldTShift;
          state.sCount[ddLine] = oldSCount;
          state.tight = oldTight;
          state.parentType = oldParentType;
          state.blkIndent = oldIndent;
          state.ddIndent = oldDDIndent;
          token = state.push("dd_close", "dd", -1);
          itemLines[1] = nextLine = state.line;
          if (nextLine >= endLine) {
            break OUTER;
          }
          if (state.sCount[nextLine] < state.blkIndent) {
            break OUTER;
          }
          contentStart = skipMarker(state, nextLine);
          if (contentStart < 0) {
            break;
          }
          ddLine = nextLine;
          // go to the next loop iteration:
          // insert DD tag and repeat checking
                }
        if (nextLine >= endLine) {
          break;
        }
        dtLine = nextLine;
        if (state.isEmpty(dtLine)) {
          break;
        }
        if (state.sCount[dtLine] < state.blkIndent) {
          break;
        }
        ddLine = dtLine + 1;
        if (ddLine >= endLine) {
          break;
        }
        if (state.isEmpty(ddLine)) {
          ddLine++;
        }
        if (ddLine >= endLine) {
          break;
        }
        if (state.sCount[ddLine] < state.blkIndent) {
          break;
        }
        contentStart = skipMarker(state, ddLine);
        if (contentStart < 0) {
          break;
        }
        // go to the next loop iteration:
        // insert DT and DD tags and repeat checking
            }
      // Finilize list
            token = state.push("dl_close", "dl", -1);
      listLines[1] = nextLine;
      state.line = nextLine;
      // mark paragraphs tight if needed
            if (tight) {
        markTightParagraphs(state, listTokIdx);
      }
      return true;
    }
    md.block.ruler.before("paragraph", "deflist", deflist, {
      alt: [ "paragraph", "reference", "blockquote" ]
    });
  };
  var emojies_defs = {
    100: "\ud83d\udcaf",
    1234: "\ud83d\udd22",
    grinning: "\ud83d\ude00",
    smiley: "\ud83d\ude03",
    smile: "\ud83d\ude04",
    grin: "\ud83d\ude01",
    laughing: "\ud83d\ude06",
    satisfied: "\ud83d\ude06",
    sweat_smile: "\ud83d\ude05",
    rofl: "\ud83e\udd23",
    joy: "\ud83d\ude02",
    slightly_smiling_face: "\ud83d\ude42",
    upside_down_face: "\ud83d\ude43",
    wink: "\ud83d\ude09",
    blush: "\ud83d\ude0a",
    innocent: "\ud83d\ude07",
    smiling_face_with_three_hearts: "\ud83e\udd70",
    heart_eyes: "\ud83d\ude0d",
    star_struck: "\ud83e\udd29",
    kissing_heart: "\ud83d\ude18",
    kissing: "\ud83d\ude17",
    relaxed: "\u263a\ufe0f",
    kissing_closed_eyes: "\ud83d\ude1a",
    kissing_smiling_eyes: "\ud83d\ude19",
    smiling_face_with_tear: "\ud83e\udd72",
    yum: "\ud83d\ude0b",
    stuck_out_tongue: "\ud83d\ude1b",
    stuck_out_tongue_winking_eye: "\ud83d\ude1c",
    zany_face: "\ud83e\udd2a",
    stuck_out_tongue_closed_eyes: "\ud83d\ude1d",
    money_mouth_face: "\ud83e\udd11",
    hugs: "\ud83e\udd17",
    hand_over_mouth: "\ud83e\udd2d",
    shushing_face: "\ud83e\udd2b",
    thinking: "\ud83e\udd14",
    zipper_mouth_face: "\ud83e\udd10",
    raised_eyebrow: "\ud83e\udd28",
    neutral_face: "\ud83d\ude10",
    expressionless: "\ud83d\ude11",
    no_mouth: "\ud83d\ude36",
    smirk: "\ud83d\ude0f",
    unamused: "\ud83d\ude12",
    roll_eyes: "\ud83d\ude44",
    grimacing: "\ud83d\ude2c",
    lying_face: "\ud83e\udd25",
    relieved: "\ud83d\ude0c",
    pensive: "\ud83d\ude14",
    sleepy: "\ud83d\ude2a",
    drooling_face: "\ud83e\udd24",
    sleeping: "\ud83d\ude34",
    mask: "\ud83d\ude37",
    face_with_thermometer: "\ud83e\udd12",
    face_with_head_bandage: "\ud83e\udd15",
    nauseated_face: "\ud83e\udd22",
    vomiting_face: "\ud83e\udd2e",
    sneezing_face: "\ud83e\udd27",
    hot_face: "\ud83e\udd75",
    cold_face: "\ud83e\udd76",
    woozy_face: "\ud83e\udd74",
    dizzy_face: "\ud83d\ude35",
    exploding_head: "\ud83e\udd2f",
    cowboy_hat_face: "\ud83e\udd20",
    partying_face: "\ud83e\udd73",
    disguised_face: "\ud83e\udd78",
    sunglasses: "\ud83d\ude0e",
    nerd_face: "\ud83e\udd13",
    monocle_face: "\ud83e\uddd0",
    confused: "\ud83d\ude15",
    worried: "\ud83d\ude1f",
    slightly_frowning_face: "\ud83d\ude41",
    frowning_face: "\u2639\ufe0f",
    open_mouth: "\ud83d\ude2e",
    hushed: "\ud83d\ude2f",
    astonished: "\ud83d\ude32",
    flushed: "\ud83d\ude33",
    pleading_face: "\ud83e\udd7a",
    frowning: "\ud83d\ude26",
    anguished: "\ud83d\ude27",
    fearful: "\ud83d\ude28",
    cold_sweat: "\ud83d\ude30",
    disappointed_relieved: "\ud83d\ude25",
    cry: "\ud83d\ude22",
    sob: "\ud83d\ude2d",
    scream: "\ud83d\ude31",
    confounded: "\ud83d\ude16",
    persevere: "\ud83d\ude23",
    disappointed: "\ud83d\ude1e",
    sweat: "\ud83d\ude13",
    weary: "\ud83d\ude29",
    tired_face: "\ud83d\ude2b",
    yawning_face: "\ud83e\udd71",
    triumph: "\ud83d\ude24",
    rage: "\ud83d\ude21",
    pout: "\ud83d\ude21",
    angry: "\ud83d\ude20",
    cursing_face: "\ud83e\udd2c",
    smiling_imp: "\ud83d\ude08",
    imp: "\ud83d\udc7f",
    skull: "\ud83d\udc80",
    skull_and_crossbones: "\u2620\ufe0f",
    hankey: "\ud83d\udca9",
    poop: "\ud83d\udca9",
    shit: "\ud83d\udca9",
    clown_face: "\ud83e\udd21",
    japanese_ogre: "\ud83d\udc79",
    japanese_goblin: "\ud83d\udc7a",
    ghost: "\ud83d\udc7b",
    alien: "\ud83d\udc7d",
    space_invader: "\ud83d\udc7e",
    robot: "\ud83e\udd16",
    smiley_cat: "\ud83d\ude3a",
    smile_cat: "\ud83d\ude38",
    joy_cat: "\ud83d\ude39",
    heart_eyes_cat: "\ud83d\ude3b",
    smirk_cat: "\ud83d\ude3c",
    kissing_cat: "\ud83d\ude3d",
    scream_cat: "\ud83d\ude40",
    crying_cat_face: "\ud83d\ude3f",
    pouting_cat: "\ud83d\ude3e",
    see_no_evil: "\ud83d\ude48",
    hear_no_evil: "\ud83d\ude49",
    speak_no_evil: "\ud83d\ude4a",
    kiss: "\ud83d\udc8b",
    love_letter: "\ud83d\udc8c",
    cupid: "\ud83d\udc98",
    gift_heart: "\ud83d\udc9d",
    sparkling_heart: "\ud83d\udc96",
    heartpulse: "\ud83d\udc97",
    heartbeat: "\ud83d\udc93",
    revolving_hearts: "\ud83d\udc9e",
    two_hearts: "\ud83d\udc95",
    heart_decoration: "\ud83d\udc9f",
    heavy_heart_exclamation: "\u2763\ufe0f",
    broken_heart: "\ud83d\udc94",
    heart: "\u2764\ufe0f",
    orange_heart: "\ud83e\udde1",
    yellow_heart: "\ud83d\udc9b",
    green_heart: "\ud83d\udc9a",
    blue_heart: "\ud83d\udc99",
    purple_heart: "\ud83d\udc9c",
    brown_heart: "\ud83e\udd0e",
    black_heart: "\ud83d\udda4",
    white_heart: "\ud83e\udd0d",
    anger: "\ud83d\udca2",
    boom: "\ud83d\udca5",
    collision: "\ud83d\udca5",
    dizzy: "\ud83d\udcab",
    sweat_drops: "\ud83d\udca6",
    dash: "\ud83d\udca8",
    hole: "\ud83d\udd73\ufe0f",
    bomb: "\ud83d\udca3",
    speech_balloon: "\ud83d\udcac",
    eye_speech_bubble: "\ud83d\udc41\ufe0f\u200d\ud83d\udde8\ufe0f",
    left_speech_bubble: "\ud83d\udde8\ufe0f",
    right_anger_bubble: "\ud83d\uddef\ufe0f",
    thought_balloon: "\ud83d\udcad",
    zzz: "\ud83d\udca4",
    wave: "\ud83d\udc4b",
    raised_back_of_hand: "\ud83e\udd1a",
    raised_hand_with_fingers_splayed: "\ud83d\udd90\ufe0f",
    hand: "\u270b",
    raised_hand: "\u270b",
    vulcan_salute: "\ud83d\udd96",
    ok_hand: "\ud83d\udc4c",
    pinched_fingers: "\ud83e\udd0c",
    pinching_hand: "\ud83e\udd0f",
    v: "\u270c\ufe0f",
    crossed_fingers: "\ud83e\udd1e",
    love_you_gesture: "\ud83e\udd1f",
    metal: "\ud83e\udd18",
    call_me_hand: "\ud83e\udd19",
    point_left: "\ud83d\udc48",
    point_right: "\ud83d\udc49",
    point_up_2: "\ud83d\udc46",
    middle_finger: "\ud83d\udd95",
    fu: "\ud83d\udd95",
    point_down: "\ud83d\udc47",
    point_up: "\u261d\ufe0f",
    "+1": "\ud83d\udc4d",
    thumbsup: "\ud83d\udc4d",
    "-1": "\ud83d\udc4e",
    thumbsdown: "\ud83d\udc4e",
    fist_raised: "\u270a",
    fist: "\u270a",
    fist_oncoming: "\ud83d\udc4a",
    facepunch: "\ud83d\udc4a",
    punch: "\ud83d\udc4a",
    fist_left: "\ud83e\udd1b",
    fist_right: "\ud83e\udd1c",
    clap: "\ud83d\udc4f",
    raised_hands: "\ud83d\ude4c",
    open_hands: "\ud83d\udc50",
    palms_up_together: "\ud83e\udd32",
    handshake: "\ud83e\udd1d",
    pray: "\ud83d\ude4f",
    writing_hand: "\u270d\ufe0f",
    nail_care: "\ud83d\udc85",
    selfie: "\ud83e\udd33",
    muscle: "\ud83d\udcaa",
    mechanical_arm: "\ud83e\uddbe",
    mechanical_leg: "\ud83e\uddbf",
    leg: "\ud83e\uddb5",
    foot: "\ud83e\uddb6",
    ear: "\ud83d\udc42",
    ear_with_hearing_aid: "\ud83e\uddbb",
    nose: "\ud83d\udc43",
    brain: "\ud83e\udde0",
    anatomical_heart: "\ud83e\udec0",
    lungs: "\ud83e\udec1",
    tooth: "\ud83e\uddb7",
    bone: "\ud83e\uddb4",
    eyes: "\ud83d\udc40",
    eye: "\ud83d\udc41\ufe0f",
    tongue: "\ud83d\udc45",
    lips: "\ud83d\udc44",
    baby: "\ud83d\udc76",
    child: "\ud83e\uddd2",
    boy: "\ud83d\udc66",
    girl: "\ud83d\udc67",
    adult: "\ud83e\uddd1",
    blond_haired_person: "\ud83d\udc71",
    man: "\ud83d\udc68",
    bearded_person: "\ud83e\uddd4",
    red_haired_man: "\ud83d\udc68\u200d\ud83e\uddb0",
    curly_haired_man: "\ud83d\udc68\u200d\ud83e\uddb1",
    white_haired_man: "\ud83d\udc68\u200d\ud83e\uddb3",
    bald_man: "\ud83d\udc68\u200d\ud83e\uddb2",
    woman: "\ud83d\udc69",
    red_haired_woman: "\ud83d\udc69\u200d\ud83e\uddb0",
    person_red_hair: "\ud83e\uddd1\u200d\ud83e\uddb0",
    curly_haired_woman: "\ud83d\udc69\u200d\ud83e\uddb1",
    person_curly_hair: "\ud83e\uddd1\u200d\ud83e\uddb1",
    white_haired_woman: "\ud83d\udc69\u200d\ud83e\uddb3",
    person_white_hair: "\ud83e\uddd1\u200d\ud83e\uddb3",
    bald_woman: "\ud83d\udc69\u200d\ud83e\uddb2",
    person_bald: "\ud83e\uddd1\u200d\ud83e\uddb2",
    blond_haired_woman: "\ud83d\udc71\u200d\u2640\ufe0f",
    blonde_woman: "\ud83d\udc71\u200d\u2640\ufe0f",
    blond_haired_man: "\ud83d\udc71\u200d\u2642\ufe0f",
    older_adult: "\ud83e\uddd3",
    older_man: "\ud83d\udc74",
    older_woman: "\ud83d\udc75",
    frowning_person: "\ud83d\ude4d",
    frowning_man: "\ud83d\ude4d\u200d\u2642\ufe0f",
    frowning_woman: "\ud83d\ude4d\u200d\u2640\ufe0f",
    pouting_face: "\ud83d\ude4e",
    pouting_man: "\ud83d\ude4e\u200d\u2642\ufe0f",
    pouting_woman: "\ud83d\ude4e\u200d\u2640\ufe0f",
    no_good: "\ud83d\ude45",
    no_good_man: "\ud83d\ude45\u200d\u2642\ufe0f",
    ng_man: "\ud83d\ude45\u200d\u2642\ufe0f",
    no_good_woman: "\ud83d\ude45\u200d\u2640\ufe0f",
    ng_woman: "\ud83d\ude45\u200d\u2640\ufe0f",
    ok_person: "\ud83d\ude46",
    ok_man: "\ud83d\ude46\u200d\u2642\ufe0f",
    ok_woman: "\ud83d\ude46\u200d\u2640\ufe0f",
    tipping_hand_person: "\ud83d\udc81",
    information_desk_person: "\ud83d\udc81",
    tipping_hand_man: "\ud83d\udc81\u200d\u2642\ufe0f",
    sassy_man: "\ud83d\udc81\u200d\u2642\ufe0f",
    tipping_hand_woman: "\ud83d\udc81\u200d\u2640\ufe0f",
    sassy_woman: "\ud83d\udc81\u200d\u2640\ufe0f",
    raising_hand: "\ud83d\ude4b",
    raising_hand_man: "\ud83d\ude4b\u200d\u2642\ufe0f",
    raising_hand_woman: "\ud83d\ude4b\u200d\u2640\ufe0f",
    deaf_person: "\ud83e\uddcf",
    deaf_man: "\ud83e\uddcf\u200d\u2642\ufe0f",
    deaf_woman: "\ud83e\uddcf\u200d\u2640\ufe0f",
    bow: "\ud83d\ude47",
    bowing_man: "\ud83d\ude47\u200d\u2642\ufe0f",
    bowing_woman: "\ud83d\ude47\u200d\u2640\ufe0f",
    facepalm: "\ud83e\udd26",
    man_facepalming: "\ud83e\udd26\u200d\u2642\ufe0f",
    woman_facepalming: "\ud83e\udd26\u200d\u2640\ufe0f",
    shrug: "\ud83e\udd37",
    man_shrugging: "\ud83e\udd37\u200d\u2642\ufe0f",
    woman_shrugging: "\ud83e\udd37\u200d\u2640\ufe0f",
    health_worker: "\ud83e\uddd1\u200d\u2695\ufe0f",
    man_health_worker: "\ud83d\udc68\u200d\u2695\ufe0f",
    woman_health_worker: "\ud83d\udc69\u200d\u2695\ufe0f",
    student: "\ud83e\uddd1\u200d\ud83c\udf93",
    man_student: "\ud83d\udc68\u200d\ud83c\udf93",
    woman_student: "\ud83d\udc69\u200d\ud83c\udf93",
    teacher: "\ud83e\uddd1\u200d\ud83c\udfeb",
    man_teacher: "\ud83d\udc68\u200d\ud83c\udfeb",
    woman_teacher: "\ud83d\udc69\u200d\ud83c\udfeb",
    judge: "\ud83e\uddd1\u200d\u2696\ufe0f",
    man_judge: "\ud83d\udc68\u200d\u2696\ufe0f",
    woman_judge: "\ud83d\udc69\u200d\u2696\ufe0f",
    farmer: "\ud83e\uddd1\u200d\ud83c\udf3e",
    man_farmer: "\ud83d\udc68\u200d\ud83c\udf3e",
    woman_farmer: "\ud83d\udc69\u200d\ud83c\udf3e",
    cook: "\ud83e\uddd1\u200d\ud83c\udf73",
    man_cook: "\ud83d\udc68\u200d\ud83c\udf73",
    woman_cook: "\ud83d\udc69\u200d\ud83c\udf73",
    mechanic: "\ud83e\uddd1\u200d\ud83d\udd27",
    man_mechanic: "\ud83d\udc68\u200d\ud83d\udd27",
    woman_mechanic: "\ud83d\udc69\u200d\ud83d\udd27",
    factory_worker: "\ud83e\uddd1\u200d\ud83c\udfed",
    man_factory_worker: "\ud83d\udc68\u200d\ud83c\udfed",
    woman_factory_worker: "\ud83d\udc69\u200d\ud83c\udfed",
    office_worker: "\ud83e\uddd1\u200d\ud83d\udcbc",
    man_office_worker: "\ud83d\udc68\u200d\ud83d\udcbc",
    woman_office_worker: "\ud83d\udc69\u200d\ud83d\udcbc",
    scientist: "\ud83e\uddd1\u200d\ud83d\udd2c",
    man_scientist: "\ud83d\udc68\u200d\ud83d\udd2c",
    woman_scientist: "\ud83d\udc69\u200d\ud83d\udd2c",
    technologist: "\ud83e\uddd1\u200d\ud83d\udcbb",
    man_technologist: "\ud83d\udc68\u200d\ud83d\udcbb",
    woman_technologist: "\ud83d\udc69\u200d\ud83d\udcbb",
    singer: "\ud83e\uddd1\u200d\ud83c\udfa4",
    man_singer: "\ud83d\udc68\u200d\ud83c\udfa4",
    woman_singer: "\ud83d\udc69\u200d\ud83c\udfa4",
    artist: "\ud83e\uddd1\u200d\ud83c\udfa8",
    man_artist: "\ud83d\udc68\u200d\ud83c\udfa8",
    woman_artist: "\ud83d\udc69\u200d\ud83c\udfa8",
    pilot: "\ud83e\uddd1\u200d\u2708\ufe0f",
    man_pilot: "\ud83d\udc68\u200d\u2708\ufe0f",
    woman_pilot: "\ud83d\udc69\u200d\u2708\ufe0f",
    astronaut: "\ud83e\uddd1\u200d\ud83d\ude80",
    man_astronaut: "\ud83d\udc68\u200d\ud83d\ude80",
    woman_astronaut: "\ud83d\udc69\u200d\ud83d\ude80",
    firefighter: "\ud83e\uddd1\u200d\ud83d\ude92",
    man_firefighter: "\ud83d\udc68\u200d\ud83d\ude92",
    woman_firefighter: "\ud83d\udc69\u200d\ud83d\ude92",
    police_officer: "\ud83d\udc6e",
    cop: "\ud83d\udc6e",
    policeman: "\ud83d\udc6e\u200d\u2642\ufe0f",
    policewoman: "\ud83d\udc6e\u200d\u2640\ufe0f",
    detective: "\ud83d\udd75\ufe0f",
    male_detective: "\ud83d\udd75\ufe0f\u200d\u2642\ufe0f",
    female_detective: "\ud83d\udd75\ufe0f\u200d\u2640\ufe0f",
    guard: "\ud83d\udc82",
    guardsman: "\ud83d\udc82\u200d\u2642\ufe0f",
    guardswoman: "\ud83d\udc82\u200d\u2640\ufe0f",
    ninja: "\ud83e\udd77",
    construction_worker: "\ud83d\udc77",
    construction_worker_man: "\ud83d\udc77\u200d\u2642\ufe0f",
    construction_worker_woman: "\ud83d\udc77\u200d\u2640\ufe0f",
    prince: "\ud83e\udd34",
    princess: "\ud83d\udc78",
    person_with_turban: "\ud83d\udc73",
    man_with_turban: "\ud83d\udc73\u200d\u2642\ufe0f",
    woman_with_turban: "\ud83d\udc73\u200d\u2640\ufe0f",
    man_with_gua_pi_mao: "\ud83d\udc72",
    woman_with_headscarf: "\ud83e\uddd5",
    person_in_tuxedo: "\ud83e\udd35",
    man_in_tuxedo: "\ud83e\udd35\u200d\u2642\ufe0f",
    woman_in_tuxedo: "\ud83e\udd35\u200d\u2640\ufe0f",
    person_with_veil: "\ud83d\udc70",
    man_with_veil: "\ud83d\udc70\u200d\u2642\ufe0f",
    woman_with_veil: "\ud83d\udc70\u200d\u2640\ufe0f",
    bride_with_veil: "\ud83d\udc70\u200d\u2640\ufe0f",
    pregnant_woman: "\ud83e\udd30",
    breast_feeding: "\ud83e\udd31",
    woman_feeding_baby: "\ud83d\udc69\u200d\ud83c\udf7c",
    man_feeding_baby: "\ud83d\udc68\u200d\ud83c\udf7c",
    person_feeding_baby: "\ud83e\uddd1\u200d\ud83c\udf7c",
    angel: "\ud83d\udc7c",
    santa: "\ud83c\udf85",
    mrs_claus: "\ud83e\udd36",
    mx_claus: "\ud83e\uddd1\u200d\ud83c\udf84",
    superhero: "\ud83e\uddb8",
    superhero_man: "\ud83e\uddb8\u200d\u2642\ufe0f",
    superhero_woman: "\ud83e\uddb8\u200d\u2640\ufe0f",
    supervillain: "\ud83e\uddb9",
    supervillain_man: "\ud83e\uddb9\u200d\u2642\ufe0f",
    supervillain_woman: "\ud83e\uddb9\u200d\u2640\ufe0f",
    mage: "\ud83e\uddd9",
    mage_man: "\ud83e\uddd9\u200d\u2642\ufe0f",
    mage_woman: "\ud83e\uddd9\u200d\u2640\ufe0f",
    fairy: "\ud83e\uddda",
    fairy_man: "\ud83e\uddda\u200d\u2642\ufe0f",
    fairy_woman: "\ud83e\uddda\u200d\u2640\ufe0f",
    vampire: "\ud83e\udddb",
    vampire_man: "\ud83e\udddb\u200d\u2642\ufe0f",
    vampire_woman: "\ud83e\udddb\u200d\u2640\ufe0f",
    merperson: "\ud83e\udddc",
    merman: "\ud83e\udddc\u200d\u2642\ufe0f",
    mermaid: "\ud83e\udddc\u200d\u2640\ufe0f",
    elf: "\ud83e\udddd",
    elf_man: "\ud83e\udddd\u200d\u2642\ufe0f",
    elf_woman: "\ud83e\udddd\u200d\u2640\ufe0f",
    genie: "\ud83e\uddde",
    genie_man: "\ud83e\uddde\u200d\u2642\ufe0f",
    genie_woman: "\ud83e\uddde\u200d\u2640\ufe0f",
    zombie: "\ud83e\udddf",
    zombie_man: "\ud83e\udddf\u200d\u2642\ufe0f",
    zombie_woman: "\ud83e\udddf\u200d\u2640\ufe0f",
    massage: "\ud83d\udc86",
    massage_man: "\ud83d\udc86\u200d\u2642\ufe0f",
    massage_woman: "\ud83d\udc86\u200d\u2640\ufe0f",
    haircut: "\ud83d\udc87",
    haircut_man: "\ud83d\udc87\u200d\u2642\ufe0f",
    haircut_woman: "\ud83d\udc87\u200d\u2640\ufe0f",
    walking: "\ud83d\udeb6",
    walking_man: "\ud83d\udeb6\u200d\u2642\ufe0f",
    walking_woman: "\ud83d\udeb6\u200d\u2640\ufe0f",
    standing_person: "\ud83e\uddcd",
    standing_man: "\ud83e\uddcd\u200d\u2642\ufe0f",
    standing_woman: "\ud83e\uddcd\u200d\u2640\ufe0f",
    kneeling_person: "\ud83e\uddce",
    kneeling_man: "\ud83e\uddce\u200d\u2642\ufe0f",
    kneeling_woman: "\ud83e\uddce\u200d\u2640\ufe0f",
    person_with_probing_cane: "\ud83e\uddd1\u200d\ud83e\uddaf",
    man_with_probing_cane: "\ud83d\udc68\u200d\ud83e\uddaf",
    woman_with_probing_cane: "\ud83d\udc69\u200d\ud83e\uddaf",
    person_in_motorized_wheelchair: "\ud83e\uddd1\u200d\ud83e\uddbc",
    man_in_motorized_wheelchair: "\ud83d\udc68\u200d\ud83e\uddbc",
    woman_in_motorized_wheelchair: "\ud83d\udc69\u200d\ud83e\uddbc",
    person_in_manual_wheelchair: "\ud83e\uddd1\u200d\ud83e\uddbd",
    man_in_manual_wheelchair: "\ud83d\udc68\u200d\ud83e\uddbd",
    woman_in_manual_wheelchair: "\ud83d\udc69\u200d\ud83e\uddbd",
    runner: "\ud83c\udfc3",
    running: "\ud83c\udfc3",
    running_man: "\ud83c\udfc3\u200d\u2642\ufe0f",
    running_woman: "\ud83c\udfc3\u200d\u2640\ufe0f",
    woman_dancing: "\ud83d\udc83",
    dancer: "\ud83d\udc83",
    man_dancing: "\ud83d\udd7a",
    business_suit_levitating: "\ud83d\udd74\ufe0f",
    dancers: "\ud83d\udc6f",
    dancing_men: "\ud83d\udc6f\u200d\u2642\ufe0f",
    dancing_women: "\ud83d\udc6f\u200d\u2640\ufe0f",
    sauna_person: "\ud83e\uddd6",
    sauna_man: "\ud83e\uddd6\u200d\u2642\ufe0f",
    sauna_woman: "\ud83e\uddd6\u200d\u2640\ufe0f",
    climbing: "\ud83e\uddd7",
    climbing_man: "\ud83e\uddd7\u200d\u2642\ufe0f",
    climbing_woman: "\ud83e\uddd7\u200d\u2640\ufe0f",
    person_fencing: "\ud83e\udd3a",
    horse_racing: "\ud83c\udfc7",
    skier: "\u26f7\ufe0f",
    snowboarder: "\ud83c\udfc2",
    golfing: "\ud83c\udfcc\ufe0f",
    golfing_man: "\ud83c\udfcc\ufe0f\u200d\u2642\ufe0f",
    golfing_woman: "\ud83c\udfcc\ufe0f\u200d\u2640\ufe0f",
    surfer: "\ud83c\udfc4",
    surfing_man: "\ud83c\udfc4\u200d\u2642\ufe0f",
    surfing_woman: "\ud83c\udfc4\u200d\u2640\ufe0f",
    rowboat: "\ud83d\udea3",
    rowing_man: "\ud83d\udea3\u200d\u2642\ufe0f",
    rowing_woman: "\ud83d\udea3\u200d\u2640\ufe0f",
    swimmer: "\ud83c\udfca",
    swimming_man: "\ud83c\udfca\u200d\u2642\ufe0f",
    swimming_woman: "\ud83c\udfca\u200d\u2640\ufe0f",
    bouncing_ball_person: "\u26f9\ufe0f",
    bouncing_ball_man: "\u26f9\ufe0f\u200d\u2642\ufe0f",
    basketball_man: "\u26f9\ufe0f\u200d\u2642\ufe0f",
    bouncing_ball_woman: "\u26f9\ufe0f\u200d\u2640\ufe0f",
    basketball_woman: "\u26f9\ufe0f\u200d\u2640\ufe0f",
    weight_lifting: "\ud83c\udfcb\ufe0f",
    weight_lifting_man: "\ud83c\udfcb\ufe0f\u200d\u2642\ufe0f",
    weight_lifting_woman: "\ud83c\udfcb\ufe0f\u200d\u2640\ufe0f",
    bicyclist: "\ud83d\udeb4",
    biking_man: "\ud83d\udeb4\u200d\u2642\ufe0f",
    biking_woman: "\ud83d\udeb4\u200d\u2640\ufe0f",
    mountain_bicyclist: "\ud83d\udeb5",
    mountain_biking_man: "\ud83d\udeb5\u200d\u2642\ufe0f",
    mountain_biking_woman: "\ud83d\udeb5\u200d\u2640\ufe0f",
    cartwheeling: "\ud83e\udd38",
    man_cartwheeling: "\ud83e\udd38\u200d\u2642\ufe0f",
    woman_cartwheeling: "\ud83e\udd38\u200d\u2640\ufe0f",
    wrestling: "\ud83e\udd3c",
    men_wrestling: "\ud83e\udd3c\u200d\u2642\ufe0f",
    women_wrestling: "\ud83e\udd3c\u200d\u2640\ufe0f",
    water_polo: "\ud83e\udd3d",
    man_playing_water_polo: "\ud83e\udd3d\u200d\u2642\ufe0f",
    woman_playing_water_polo: "\ud83e\udd3d\u200d\u2640\ufe0f",
    handball_person: "\ud83e\udd3e",
    man_playing_handball: "\ud83e\udd3e\u200d\u2642\ufe0f",
    woman_playing_handball: "\ud83e\udd3e\u200d\u2640\ufe0f",
    juggling_person: "\ud83e\udd39",
    man_juggling: "\ud83e\udd39\u200d\u2642\ufe0f",
    woman_juggling: "\ud83e\udd39\u200d\u2640\ufe0f",
    lotus_position: "\ud83e\uddd8",
    lotus_position_man: "\ud83e\uddd8\u200d\u2642\ufe0f",
    lotus_position_woman: "\ud83e\uddd8\u200d\u2640\ufe0f",
    bath: "\ud83d\udec0",
    sleeping_bed: "\ud83d\udecc",
    people_holding_hands: "\ud83e\uddd1\u200d\ud83e\udd1d\u200d\ud83e\uddd1",
    two_women_holding_hands: "\ud83d\udc6d",
    couple: "\ud83d\udc6b",
    two_men_holding_hands: "\ud83d\udc6c",
    couplekiss: "\ud83d\udc8f",
    couplekiss_man_woman: "\ud83d\udc69\u200d\u2764\ufe0f\u200d\ud83d\udc8b\u200d\ud83d\udc68",
    couplekiss_man_man: "\ud83d\udc68\u200d\u2764\ufe0f\u200d\ud83d\udc8b\u200d\ud83d\udc68",
    couplekiss_woman_woman: "\ud83d\udc69\u200d\u2764\ufe0f\u200d\ud83d\udc8b\u200d\ud83d\udc69",
    couple_with_heart: "\ud83d\udc91",
    couple_with_heart_woman_man: "\ud83d\udc69\u200d\u2764\ufe0f\u200d\ud83d\udc68",
    couple_with_heart_man_man: "\ud83d\udc68\u200d\u2764\ufe0f\u200d\ud83d\udc68",
    couple_with_heart_woman_woman: "\ud83d\udc69\u200d\u2764\ufe0f\u200d\ud83d\udc69",
    family: "\ud83d\udc6a",
    family_man_woman_boy: "\ud83d\udc68\u200d\ud83d\udc69\u200d\ud83d\udc66",
    family_man_woman_girl: "\ud83d\udc68\u200d\ud83d\udc69\u200d\ud83d\udc67",
    family_man_woman_girl_boy: "\ud83d\udc68\u200d\ud83d\udc69\u200d\ud83d\udc67\u200d\ud83d\udc66",
    family_man_woman_boy_boy: "\ud83d\udc68\u200d\ud83d\udc69\u200d\ud83d\udc66\u200d\ud83d\udc66",
    family_man_woman_girl_girl: "\ud83d\udc68\u200d\ud83d\udc69\u200d\ud83d\udc67\u200d\ud83d\udc67",
    family_man_man_boy: "\ud83d\udc68\u200d\ud83d\udc68\u200d\ud83d\udc66",
    family_man_man_girl: "\ud83d\udc68\u200d\ud83d\udc68\u200d\ud83d\udc67",
    family_man_man_girl_boy: "\ud83d\udc68\u200d\ud83d\udc68\u200d\ud83d\udc67\u200d\ud83d\udc66",
    family_man_man_boy_boy: "\ud83d\udc68\u200d\ud83d\udc68\u200d\ud83d\udc66\u200d\ud83d\udc66",
    family_man_man_girl_girl: "\ud83d\udc68\u200d\ud83d\udc68\u200d\ud83d\udc67\u200d\ud83d\udc67",
    family_woman_woman_boy: "\ud83d\udc69\u200d\ud83d\udc69\u200d\ud83d\udc66",
    family_woman_woman_girl: "\ud83d\udc69\u200d\ud83d\udc69\u200d\ud83d\udc67",
    family_woman_woman_girl_boy: "\ud83d\udc69\u200d\ud83d\udc69\u200d\ud83d\udc67\u200d\ud83d\udc66",
    family_woman_woman_boy_boy: "\ud83d\udc69\u200d\ud83d\udc69\u200d\ud83d\udc66\u200d\ud83d\udc66",
    family_woman_woman_girl_girl: "\ud83d\udc69\u200d\ud83d\udc69\u200d\ud83d\udc67\u200d\ud83d\udc67",
    family_man_boy: "\ud83d\udc68\u200d\ud83d\udc66",
    family_man_boy_boy: "\ud83d\udc68\u200d\ud83d\udc66\u200d\ud83d\udc66",
    family_man_girl: "\ud83d\udc68\u200d\ud83d\udc67",
    family_man_girl_boy: "\ud83d\udc68\u200d\ud83d\udc67\u200d\ud83d\udc66",
    family_man_girl_girl: "\ud83d\udc68\u200d\ud83d\udc67\u200d\ud83d\udc67",
    family_woman_boy: "\ud83d\udc69\u200d\ud83d\udc66",
    family_woman_boy_boy: "\ud83d\udc69\u200d\ud83d\udc66\u200d\ud83d\udc66",
    family_woman_girl: "\ud83d\udc69\u200d\ud83d\udc67",
    family_woman_girl_boy: "\ud83d\udc69\u200d\ud83d\udc67\u200d\ud83d\udc66",
    family_woman_girl_girl: "\ud83d\udc69\u200d\ud83d\udc67\u200d\ud83d\udc67",
    speaking_head: "\ud83d\udde3\ufe0f",
    bust_in_silhouette: "\ud83d\udc64",
    busts_in_silhouette: "\ud83d\udc65",
    people_hugging: "\ud83e\udec2",
    footprints: "\ud83d\udc63",
    monkey_face: "\ud83d\udc35",
    monkey: "\ud83d\udc12",
    gorilla: "\ud83e\udd8d",
    orangutan: "\ud83e\udda7",
    dog: "\ud83d\udc36",
    dog2: "\ud83d\udc15",
    guide_dog: "\ud83e\uddae",
    service_dog: "\ud83d\udc15\u200d\ud83e\uddba",
    poodle: "\ud83d\udc29",
    wolf: "\ud83d\udc3a",
    fox_face: "\ud83e\udd8a",
    raccoon: "\ud83e\udd9d",
    cat: "\ud83d\udc31",
    cat2: "\ud83d\udc08",
    black_cat: "\ud83d\udc08\u200d\u2b1b",
    lion: "\ud83e\udd81",
    tiger: "\ud83d\udc2f",
    tiger2: "\ud83d\udc05",
    leopard: "\ud83d\udc06",
    horse: "\ud83d\udc34",
    racehorse: "\ud83d\udc0e",
    unicorn: "\ud83e\udd84",
    zebra: "\ud83e\udd93",
    deer: "\ud83e\udd8c",
    bison: "\ud83e\uddac",
    cow: "\ud83d\udc2e",
    ox: "\ud83d\udc02",
    water_buffalo: "\ud83d\udc03",
    cow2: "\ud83d\udc04",
    pig: "\ud83d\udc37",
    pig2: "\ud83d\udc16",
    boar: "\ud83d\udc17",
    pig_nose: "\ud83d\udc3d",
    ram: "\ud83d\udc0f",
    sheep: "\ud83d\udc11",
    goat: "\ud83d\udc10",
    dromedary_camel: "\ud83d\udc2a",
    camel: "\ud83d\udc2b",
    llama: "\ud83e\udd99",
    giraffe: "\ud83e\udd92",
    elephant: "\ud83d\udc18",
    mammoth: "\ud83e\udda3",
    rhinoceros: "\ud83e\udd8f",
    hippopotamus: "\ud83e\udd9b",
    mouse: "\ud83d\udc2d",
    mouse2: "\ud83d\udc01",
    rat: "\ud83d\udc00",
    hamster: "\ud83d\udc39",
    rabbit: "\ud83d\udc30",
    rabbit2: "\ud83d\udc07",
    chipmunk: "\ud83d\udc3f\ufe0f",
    beaver: "\ud83e\uddab",
    hedgehog: "\ud83e\udd94",
    bat: "\ud83e\udd87",
    bear: "\ud83d\udc3b",
    polar_bear: "\ud83d\udc3b\u200d\u2744\ufe0f",
    koala: "\ud83d\udc28",
    panda_face: "\ud83d\udc3c",
    sloth: "\ud83e\udda5",
    otter: "\ud83e\udda6",
    skunk: "\ud83e\udda8",
    kangaroo: "\ud83e\udd98",
    badger: "\ud83e\udda1",
    feet: "\ud83d\udc3e",
    paw_prints: "\ud83d\udc3e",
    turkey: "\ud83e\udd83",
    chicken: "\ud83d\udc14",
    rooster: "\ud83d\udc13",
    hatching_chick: "\ud83d\udc23",
    baby_chick: "\ud83d\udc24",
    hatched_chick: "\ud83d\udc25",
    bird: "\ud83d\udc26",
    penguin: "\ud83d\udc27",
    dove: "\ud83d\udd4a\ufe0f",
    eagle: "\ud83e\udd85",
    duck: "\ud83e\udd86",
    swan: "\ud83e\udda2",
    owl: "\ud83e\udd89",
    dodo: "\ud83e\udda4",
    feather: "\ud83e\udeb6",
    flamingo: "\ud83e\udda9",
    peacock: "\ud83e\udd9a",
    parrot: "\ud83e\udd9c",
    frog: "\ud83d\udc38",
    crocodile: "\ud83d\udc0a",
    turtle: "\ud83d\udc22",
    lizard: "\ud83e\udd8e",
    snake: "\ud83d\udc0d",
    dragon_face: "\ud83d\udc32",
    dragon: "\ud83d\udc09",
    sauropod: "\ud83e\udd95",
    "t-rex": "\ud83e\udd96",
    whale: "\ud83d\udc33",
    whale2: "\ud83d\udc0b",
    dolphin: "\ud83d\udc2c",
    flipper: "\ud83d\udc2c",
    seal: "\ud83e\uddad",
    fish: "\ud83d\udc1f",
    tropical_fish: "\ud83d\udc20",
    blowfish: "\ud83d\udc21",
    shark: "\ud83e\udd88",
    octopus: "\ud83d\udc19",
    shell: "\ud83d\udc1a",
    snail: "\ud83d\udc0c",
    butterfly: "\ud83e\udd8b",
    bug: "\ud83d\udc1b",
    ant: "\ud83d\udc1c",
    bee: "\ud83d\udc1d",
    honeybee: "\ud83d\udc1d",
    beetle: "\ud83e\udeb2",
    lady_beetle: "\ud83d\udc1e",
    cricket: "\ud83e\udd97",
    cockroach: "\ud83e\udeb3",
    spider: "\ud83d\udd77\ufe0f",
    spider_web: "\ud83d\udd78\ufe0f",
    scorpion: "\ud83e\udd82",
    mosquito: "\ud83e\udd9f",
    fly: "\ud83e\udeb0",
    worm: "\ud83e\udeb1",
    microbe: "\ud83e\udda0",
    bouquet: "\ud83d\udc90",
    cherry_blossom: "\ud83c\udf38",
    white_flower: "\ud83d\udcae",
    rosette: "\ud83c\udff5\ufe0f",
    rose: "\ud83c\udf39",
    wilted_flower: "\ud83e\udd40",
    hibiscus: "\ud83c\udf3a",
    sunflower: "\ud83c\udf3b",
    blossom: "\ud83c\udf3c",
    tulip: "\ud83c\udf37",
    seedling: "\ud83c\udf31",
    potted_plant: "\ud83e\udeb4",
    evergreen_tree: "\ud83c\udf32",
    deciduous_tree: "\ud83c\udf33",
    palm_tree: "\ud83c\udf34",
    cactus: "\ud83c\udf35",
    ear_of_rice: "\ud83c\udf3e",
    herb: "\ud83c\udf3f",
    shamrock: "\u2618\ufe0f",
    four_leaf_clover: "\ud83c\udf40",
    maple_leaf: "\ud83c\udf41",
    fallen_leaf: "\ud83c\udf42",
    leaves: "\ud83c\udf43",
    grapes: "\ud83c\udf47",
    melon: "\ud83c\udf48",
    watermelon: "\ud83c\udf49",
    tangerine: "\ud83c\udf4a",
    orange: "\ud83c\udf4a",
    mandarin: "\ud83c\udf4a",
    lemon: "\ud83c\udf4b",
    banana: "\ud83c\udf4c",
    pineapple: "\ud83c\udf4d",
    mango: "\ud83e\udd6d",
    apple: "\ud83c\udf4e",
    green_apple: "\ud83c\udf4f",
    pear: "\ud83c\udf50",
    peach: "\ud83c\udf51",
    cherries: "\ud83c\udf52",
    strawberry: "\ud83c\udf53",
    blueberries: "\ud83e\uded0",
    kiwi_fruit: "\ud83e\udd5d",
    tomato: "\ud83c\udf45",
    olive: "\ud83e\uded2",
    coconut: "\ud83e\udd65",
    avocado: "\ud83e\udd51",
    eggplant: "\ud83c\udf46",
    potato: "\ud83e\udd54",
    carrot: "\ud83e\udd55",
    corn: "\ud83c\udf3d",
    hot_pepper: "\ud83c\udf36\ufe0f",
    bell_pepper: "\ud83e\uded1",
    cucumber: "\ud83e\udd52",
    leafy_green: "\ud83e\udd6c",
    broccoli: "\ud83e\udd66",
    garlic: "\ud83e\uddc4",
    onion: "\ud83e\uddc5",
    mushroom: "\ud83c\udf44",
    peanuts: "\ud83e\udd5c",
    chestnut: "\ud83c\udf30",
    bread: "\ud83c\udf5e",
    croissant: "\ud83e\udd50",
    baguette_bread: "\ud83e\udd56",
    flatbread: "\ud83e\uded3",
    pretzel: "\ud83e\udd68",
    bagel: "\ud83e\udd6f",
    pancakes: "\ud83e\udd5e",
    waffle: "\ud83e\uddc7",
    cheese: "\ud83e\uddc0",
    meat_on_bone: "\ud83c\udf56",
    poultry_leg: "\ud83c\udf57",
    cut_of_meat: "\ud83e\udd69",
    bacon: "\ud83e\udd53",
    hamburger: "\ud83c\udf54",
    fries: "\ud83c\udf5f",
    pizza: "\ud83c\udf55",
    hotdog: "\ud83c\udf2d",
    sandwich: "\ud83e\udd6a",
    taco: "\ud83c\udf2e",
    burrito: "\ud83c\udf2f",
    tamale: "\ud83e\uded4",
    stuffed_flatbread: "\ud83e\udd59",
    falafel: "\ud83e\uddc6",
    egg: "\ud83e\udd5a",
    fried_egg: "\ud83c\udf73",
    shallow_pan_of_food: "\ud83e\udd58",
    stew: "\ud83c\udf72",
    fondue: "\ud83e\uded5",
    bowl_with_spoon: "\ud83e\udd63",
    green_salad: "\ud83e\udd57",
    popcorn: "\ud83c\udf7f",
    butter: "\ud83e\uddc8",
    salt: "\ud83e\uddc2",
    canned_food: "\ud83e\udd6b",
    bento: "\ud83c\udf71",
    rice_cracker: "\ud83c\udf58",
    rice_ball: "\ud83c\udf59",
    rice: "\ud83c\udf5a",
    curry: "\ud83c\udf5b",
    ramen: "\ud83c\udf5c",
    spaghetti: "\ud83c\udf5d",
    sweet_potato: "\ud83c\udf60",
    oden: "\ud83c\udf62",
    sushi: "\ud83c\udf63",
    fried_shrimp: "\ud83c\udf64",
    fish_cake: "\ud83c\udf65",
    moon_cake: "\ud83e\udd6e",
    dango: "\ud83c\udf61",
    dumpling: "\ud83e\udd5f",
    fortune_cookie: "\ud83e\udd60",
    takeout_box: "\ud83e\udd61",
    crab: "\ud83e\udd80",
    lobster: "\ud83e\udd9e",
    shrimp: "\ud83e\udd90",
    squid: "\ud83e\udd91",
    oyster: "\ud83e\uddaa",
    icecream: "\ud83c\udf66",
    shaved_ice: "\ud83c\udf67",
    ice_cream: "\ud83c\udf68",
    doughnut: "\ud83c\udf69",
    cookie: "\ud83c\udf6a",
    birthday: "\ud83c\udf82",
    cake: "\ud83c\udf70",
    cupcake: "\ud83e\uddc1",
    pie: "\ud83e\udd67",
    chocolate_bar: "\ud83c\udf6b",
    candy: "\ud83c\udf6c",
    lollipop: "\ud83c\udf6d",
    custard: "\ud83c\udf6e",
    honey_pot: "\ud83c\udf6f",
    baby_bottle: "\ud83c\udf7c",
    milk_glass: "\ud83e\udd5b",
    coffee: "\u2615",
    teapot: "\ud83e\uded6",
    tea: "\ud83c\udf75",
    sake: "\ud83c\udf76",
    champagne: "\ud83c\udf7e",
    wine_glass: "\ud83c\udf77",
    cocktail: "\ud83c\udf78",
    tropical_drink: "\ud83c\udf79",
    beer: "\ud83c\udf7a",
    beers: "\ud83c\udf7b",
    clinking_glasses: "\ud83e\udd42",
    tumbler_glass: "\ud83e\udd43",
    cup_with_straw: "\ud83e\udd64",
    bubble_tea: "\ud83e\uddcb",
    beverage_box: "\ud83e\uddc3",
    mate: "\ud83e\uddc9",
    ice_cube: "\ud83e\uddca",
    chopsticks: "\ud83e\udd62",
    plate_with_cutlery: "\ud83c\udf7d\ufe0f",
    fork_and_knife: "\ud83c\udf74",
    spoon: "\ud83e\udd44",
    hocho: "\ud83d\udd2a",
    knife: "\ud83d\udd2a",
    amphora: "\ud83c\udffa",
    earth_africa: "\ud83c\udf0d",
    earth_americas: "\ud83c\udf0e",
    earth_asia: "\ud83c\udf0f",
    globe_with_meridians: "\ud83c\udf10",
    world_map: "\ud83d\uddfa\ufe0f",
    japan: "\ud83d\uddfe",
    compass: "\ud83e\udded",
    mountain_snow: "\ud83c\udfd4\ufe0f",
    mountain: "\u26f0\ufe0f",
    volcano: "\ud83c\udf0b",
    mount_fuji: "\ud83d\uddfb",
    camping: "\ud83c\udfd5\ufe0f",
    beach_umbrella: "\ud83c\udfd6\ufe0f",
    desert: "\ud83c\udfdc\ufe0f",
    desert_island: "\ud83c\udfdd\ufe0f",
    national_park: "\ud83c\udfde\ufe0f",
    stadium: "\ud83c\udfdf\ufe0f",
    classical_building: "\ud83c\udfdb\ufe0f",
    building_construction: "\ud83c\udfd7\ufe0f",
    bricks: "\ud83e\uddf1",
    rock: "\ud83e\udea8",
    wood: "\ud83e\udeb5",
    hut: "\ud83d\uded6",
    houses: "\ud83c\udfd8\ufe0f",
    derelict_house: "\ud83c\udfda\ufe0f",
    house: "\ud83c\udfe0",
    house_with_garden: "\ud83c\udfe1",
    office: "\ud83c\udfe2",
    post_office: "\ud83c\udfe3",
    european_post_office: "\ud83c\udfe4",
    hospital: "\ud83c\udfe5",
    bank: "\ud83c\udfe6",
    hotel: "\ud83c\udfe8",
    love_hotel: "\ud83c\udfe9",
    convenience_store: "\ud83c\udfea",
    school: "\ud83c\udfeb",
    department_store: "\ud83c\udfec",
    factory: "\ud83c\udfed",
    japanese_castle: "\ud83c\udfef",
    european_castle: "\ud83c\udff0",
    wedding: "\ud83d\udc92",
    tokyo_tower: "\ud83d\uddfc",
    statue_of_liberty: "\ud83d\uddfd",
    church: "\u26ea",
    mosque: "\ud83d\udd4c",
    hindu_temple: "\ud83d\uded5",
    synagogue: "\ud83d\udd4d",
    shinto_shrine: "\u26e9\ufe0f",
    kaaba: "\ud83d\udd4b",
    fountain: "\u26f2",
    tent: "\u26fa",
    foggy: "\ud83c\udf01",
    night_with_stars: "\ud83c\udf03",
    cityscape: "\ud83c\udfd9\ufe0f",
    sunrise_over_mountains: "\ud83c\udf04",
    sunrise: "\ud83c\udf05",
    city_sunset: "\ud83c\udf06",
    city_sunrise: "\ud83c\udf07",
    bridge_at_night: "\ud83c\udf09",
    hotsprings: "\u2668\ufe0f",
    carousel_horse: "\ud83c\udfa0",
    ferris_wheel: "\ud83c\udfa1",
    roller_coaster: "\ud83c\udfa2",
    barber: "\ud83d\udc88",
    circus_tent: "\ud83c\udfaa",
    steam_locomotive: "\ud83d\ude82",
    railway_car: "\ud83d\ude83",
    bullettrain_side: "\ud83d\ude84",
    bullettrain_front: "\ud83d\ude85",
    train2: "\ud83d\ude86",
    metro: "\ud83d\ude87",
    light_rail: "\ud83d\ude88",
    station: "\ud83d\ude89",
    tram: "\ud83d\ude8a",
    monorail: "\ud83d\ude9d",
    mountain_railway: "\ud83d\ude9e",
    train: "\ud83d\ude8b",
    bus: "\ud83d\ude8c",
    oncoming_bus: "\ud83d\ude8d",
    trolleybus: "\ud83d\ude8e",
    minibus: "\ud83d\ude90",
    ambulance: "\ud83d\ude91",
    fire_engine: "\ud83d\ude92",
    police_car: "\ud83d\ude93",
    oncoming_police_car: "\ud83d\ude94",
    taxi: "\ud83d\ude95",
    oncoming_taxi: "\ud83d\ude96",
    car: "\ud83d\ude97",
    red_car: "\ud83d\ude97",
    oncoming_automobile: "\ud83d\ude98",
    blue_car: "\ud83d\ude99",
    pickup_truck: "\ud83d\udefb",
    truck: "\ud83d\ude9a",
    articulated_lorry: "\ud83d\ude9b",
    tractor: "\ud83d\ude9c",
    racing_car: "\ud83c\udfce\ufe0f",
    motorcycle: "\ud83c\udfcd\ufe0f",
    motor_scooter: "\ud83d\udef5",
    manual_wheelchair: "\ud83e\uddbd",
    motorized_wheelchair: "\ud83e\uddbc",
    auto_rickshaw: "\ud83d\udefa",
    bike: "\ud83d\udeb2",
    kick_scooter: "\ud83d\udef4",
    skateboard: "\ud83d\udef9",
    roller_skate: "\ud83d\udefc",
    busstop: "\ud83d\ude8f",
    motorway: "\ud83d\udee3\ufe0f",
    railway_track: "\ud83d\udee4\ufe0f",
    oil_drum: "\ud83d\udee2\ufe0f",
    fuelpump: "\u26fd",
    rotating_light: "\ud83d\udea8",
    traffic_light: "\ud83d\udea5",
    vertical_traffic_light: "\ud83d\udea6",
    stop_sign: "\ud83d\uded1",
    construction: "\ud83d\udea7",
    anchor: "\u2693",
    boat: "\u26f5",
    sailboat: "\u26f5",
    canoe: "\ud83d\udef6",
    speedboat: "\ud83d\udea4",
    passenger_ship: "\ud83d\udef3\ufe0f",
    ferry: "\u26f4\ufe0f",
    motor_boat: "\ud83d\udee5\ufe0f",
    ship: "\ud83d\udea2",
    airplane: "\u2708\ufe0f",
    small_airplane: "\ud83d\udee9\ufe0f",
    flight_departure: "\ud83d\udeeb",
    flight_arrival: "\ud83d\udeec",
    parachute: "\ud83e\ude82",
    seat: "\ud83d\udcba",
    helicopter: "\ud83d\ude81",
    suspension_railway: "\ud83d\ude9f",
    mountain_cableway: "\ud83d\udea0",
    aerial_tramway: "\ud83d\udea1",
    artificial_satellite: "\ud83d\udef0\ufe0f",
    rocket: "\ud83d\ude80",
    flying_saucer: "\ud83d\udef8",
    bellhop_bell: "\ud83d\udece\ufe0f",
    luggage: "\ud83e\uddf3",
    hourglass: "\u231b",
    hourglass_flowing_sand: "\u23f3",
    watch: "\u231a",
    alarm_clock: "\u23f0",
    stopwatch: "\u23f1\ufe0f",
    timer_clock: "\u23f2\ufe0f",
    mantelpiece_clock: "\ud83d\udd70\ufe0f",
    clock12: "\ud83d\udd5b",
    clock1230: "\ud83d\udd67",
    clock1: "\ud83d\udd50",
    clock130: "\ud83d\udd5c",
    clock2: "\ud83d\udd51",
    clock230: "\ud83d\udd5d",
    clock3: "\ud83d\udd52",
    clock330: "\ud83d\udd5e",
    clock4: "\ud83d\udd53",
    clock430: "\ud83d\udd5f",
    clock5: "\ud83d\udd54",
    clock530: "\ud83d\udd60",
    clock6: "\ud83d\udd55",
    clock630: "\ud83d\udd61",
    clock7: "\ud83d\udd56",
    clock730: "\ud83d\udd62",
    clock8: "\ud83d\udd57",
    clock830: "\ud83d\udd63",
    clock9: "\ud83d\udd58",
    clock930: "\ud83d\udd64",
    clock10: "\ud83d\udd59",
    clock1030: "\ud83d\udd65",
    clock11: "\ud83d\udd5a",
    clock1130: "\ud83d\udd66",
    new_moon: "\ud83c\udf11",
    waxing_crescent_moon: "\ud83c\udf12",
    first_quarter_moon: "\ud83c\udf13",
    moon: "\ud83c\udf14",
    waxing_gibbous_moon: "\ud83c\udf14",
    full_moon: "\ud83c\udf15",
    waning_gibbous_moon: "\ud83c\udf16",
    last_quarter_moon: "\ud83c\udf17",
    waning_crescent_moon: "\ud83c\udf18",
    crescent_moon: "\ud83c\udf19",
    new_moon_with_face: "\ud83c\udf1a",
    first_quarter_moon_with_face: "\ud83c\udf1b",
    last_quarter_moon_with_face: "\ud83c\udf1c",
    thermometer: "\ud83c\udf21\ufe0f",
    sunny: "\u2600\ufe0f",
    full_moon_with_face: "\ud83c\udf1d",
    sun_with_face: "\ud83c\udf1e",
    ringed_planet: "\ud83e\ude90",
    star: "\u2b50",
    star2: "\ud83c\udf1f",
    stars: "\ud83c\udf20",
    milky_way: "\ud83c\udf0c",
    cloud: "\u2601\ufe0f",
    partly_sunny: "\u26c5",
    cloud_with_lightning_and_rain: "\u26c8\ufe0f",
    sun_behind_small_cloud: "\ud83c\udf24\ufe0f",
    sun_behind_large_cloud: "\ud83c\udf25\ufe0f",
    sun_behind_rain_cloud: "\ud83c\udf26\ufe0f",
    cloud_with_rain: "\ud83c\udf27\ufe0f",
    cloud_with_snow: "\ud83c\udf28\ufe0f",
    cloud_with_lightning: "\ud83c\udf29\ufe0f",
    tornado: "\ud83c\udf2a\ufe0f",
    fog: "\ud83c\udf2b\ufe0f",
    wind_face: "\ud83c\udf2c\ufe0f",
    cyclone: "\ud83c\udf00",
    rainbow: "\ud83c\udf08",
    closed_umbrella: "\ud83c\udf02",
    open_umbrella: "\u2602\ufe0f",
    umbrella: "\u2614",
    parasol_on_ground: "\u26f1\ufe0f",
    zap: "\u26a1",
    snowflake: "\u2744\ufe0f",
    snowman_with_snow: "\u2603\ufe0f",
    snowman: "\u26c4",
    comet: "\u2604\ufe0f",
    fire: "\ud83d\udd25",
    droplet: "\ud83d\udca7",
    ocean: "\ud83c\udf0a",
    jack_o_lantern: "\ud83c\udf83",
    christmas_tree: "\ud83c\udf84",
    fireworks: "\ud83c\udf86",
    sparkler: "\ud83c\udf87",
    firecracker: "\ud83e\udde8",
    sparkles: "\u2728",
    balloon: "\ud83c\udf88",
    tada: "\ud83c\udf89",
    confetti_ball: "\ud83c\udf8a",
    tanabata_tree: "\ud83c\udf8b",
    bamboo: "\ud83c\udf8d",
    dolls: "\ud83c\udf8e",
    flags: "\ud83c\udf8f",
    wind_chime: "\ud83c\udf90",
    rice_scene: "\ud83c\udf91",
    red_envelope: "\ud83e\udde7",
    ribbon: "\ud83c\udf80",
    gift: "\ud83c\udf81",
    reminder_ribbon: "\ud83c\udf97\ufe0f",
    tickets: "\ud83c\udf9f\ufe0f",
    ticket: "\ud83c\udfab",
    medal_military: "\ud83c\udf96\ufe0f",
    trophy: "\ud83c\udfc6",
    medal_sports: "\ud83c\udfc5",
    "1st_place_medal": "\ud83e\udd47",
    "2nd_place_medal": "\ud83e\udd48",
    "3rd_place_medal": "\ud83e\udd49",
    soccer: "\u26bd",
    baseball: "\u26be",
    softball: "\ud83e\udd4e",
    basketball: "\ud83c\udfc0",
    volleyball: "\ud83c\udfd0",
    football: "\ud83c\udfc8",
    rugby_football: "\ud83c\udfc9",
    tennis: "\ud83c\udfbe",
    flying_disc: "\ud83e\udd4f",
    bowling: "\ud83c\udfb3",
    cricket_game: "\ud83c\udfcf",
    field_hockey: "\ud83c\udfd1",
    ice_hockey: "\ud83c\udfd2",
    lacrosse: "\ud83e\udd4d",
    ping_pong: "\ud83c\udfd3",
    badminton: "\ud83c\udff8",
    boxing_glove: "\ud83e\udd4a",
    martial_arts_uniform: "\ud83e\udd4b",
    goal_net: "\ud83e\udd45",
    golf: "\u26f3",
    ice_skate: "\u26f8\ufe0f",
    fishing_pole_and_fish: "\ud83c\udfa3",
    diving_mask: "\ud83e\udd3f",
    running_shirt_with_sash: "\ud83c\udfbd",
    ski: "\ud83c\udfbf",
    sled: "\ud83d\udef7",
    curling_stone: "\ud83e\udd4c",
    dart: "\ud83c\udfaf",
    yo_yo: "\ud83e\ude80",
    kite: "\ud83e\ude81",
    "8ball": "\ud83c\udfb1",
    crystal_ball: "\ud83d\udd2e",
    magic_wand: "\ud83e\ude84",
    nazar_amulet: "\ud83e\uddff",
    video_game: "\ud83c\udfae",
    joystick: "\ud83d\udd79\ufe0f",
    slot_machine: "\ud83c\udfb0",
    game_die: "\ud83c\udfb2",
    jigsaw: "\ud83e\udde9",
    teddy_bear: "\ud83e\uddf8",
    pinata: "\ud83e\ude85",
    nesting_dolls: "\ud83e\ude86",
    spades: "\u2660\ufe0f",
    hearts: "\u2665\ufe0f",
    diamonds: "\u2666\ufe0f",
    clubs: "\u2663\ufe0f",
    chess_pawn: "\u265f\ufe0f",
    black_joker: "\ud83c\udccf",
    mahjong: "\ud83c\udc04",
    flower_playing_cards: "\ud83c\udfb4",
    performing_arts: "\ud83c\udfad",
    framed_picture: "\ud83d\uddbc\ufe0f",
    art: "\ud83c\udfa8",
    thread: "\ud83e\uddf5",
    sewing_needle: "\ud83e\udea1",
    yarn: "\ud83e\uddf6",
    knot: "\ud83e\udea2",
    eyeglasses: "\ud83d\udc53",
    dark_sunglasses: "\ud83d\udd76\ufe0f",
    goggles: "\ud83e\udd7d",
    lab_coat: "\ud83e\udd7c",
    safety_vest: "\ud83e\uddba",
    necktie: "\ud83d\udc54",
    shirt: "\ud83d\udc55",
    tshirt: "\ud83d\udc55",
    jeans: "\ud83d\udc56",
    scarf: "\ud83e\udde3",
    gloves: "\ud83e\udde4",
    coat: "\ud83e\udde5",
    socks: "\ud83e\udde6",
    dress: "\ud83d\udc57",
    kimono: "\ud83d\udc58",
    sari: "\ud83e\udd7b",
    one_piece_swimsuit: "\ud83e\ude71",
    swim_brief: "\ud83e\ude72",
    shorts: "\ud83e\ude73",
    bikini: "\ud83d\udc59",
    womans_clothes: "\ud83d\udc5a",
    purse: "\ud83d\udc5b",
    handbag: "\ud83d\udc5c",
    pouch: "\ud83d\udc5d",
    shopping: "\ud83d\udecd\ufe0f",
    school_satchel: "\ud83c\udf92",
    thong_sandal: "\ud83e\ude74",
    mans_shoe: "\ud83d\udc5e",
    shoe: "\ud83d\udc5e",
    athletic_shoe: "\ud83d\udc5f",
    hiking_boot: "\ud83e\udd7e",
    flat_shoe: "\ud83e\udd7f",
    high_heel: "\ud83d\udc60",
    sandal: "\ud83d\udc61",
    ballet_shoes: "\ud83e\ude70",
    boot: "\ud83d\udc62",
    crown: "\ud83d\udc51",
    womans_hat: "\ud83d\udc52",
    tophat: "\ud83c\udfa9",
    mortar_board: "\ud83c\udf93",
    billed_cap: "\ud83e\udde2",
    military_helmet: "\ud83e\ude96",
    rescue_worker_helmet: "\u26d1\ufe0f",
    prayer_beads: "\ud83d\udcff",
    lipstick: "\ud83d\udc84",
    ring: "\ud83d\udc8d",
    gem: "\ud83d\udc8e",
    mute: "\ud83d\udd07",
    speaker: "\ud83d\udd08",
    sound: "\ud83d\udd09",
    loud_sound: "\ud83d\udd0a",
    loudspeaker: "\ud83d\udce2",
    mega: "\ud83d\udce3",
    postal_horn: "\ud83d\udcef",
    bell: "\ud83d\udd14",
    no_bell: "\ud83d\udd15",
    musical_score: "\ud83c\udfbc",
    musical_note: "\ud83c\udfb5",
    notes: "\ud83c\udfb6",
    studio_microphone: "\ud83c\udf99\ufe0f",
    level_slider: "\ud83c\udf9a\ufe0f",
    control_knobs: "\ud83c\udf9b\ufe0f",
    microphone: "\ud83c\udfa4",
    headphones: "\ud83c\udfa7",
    radio: "\ud83d\udcfb",
    saxophone: "\ud83c\udfb7",
    accordion: "\ud83e\ude97",
    guitar: "\ud83c\udfb8",
    musical_keyboard: "\ud83c\udfb9",
    trumpet: "\ud83c\udfba",
    violin: "\ud83c\udfbb",
    banjo: "\ud83e\ude95",
    drum: "\ud83e\udd41",
    long_drum: "\ud83e\ude98",
    iphone: "\ud83d\udcf1",
    calling: "\ud83d\udcf2",
    phone: "\u260e\ufe0f",
    telephone: "\u260e\ufe0f",
    telephone_receiver: "\ud83d\udcde",
    pager: "\ud83d\udcdf",
    fax: "\ud83d\udce0",
    battery: "\ud83d\udd0b",
    electric_plug: "\ud83d\udd0c",
    computer: "\ud83d\udcbb",
    desktop_computer: "\ud83d\udda5\ufe0f",
    printer: "\ud83d\udda8\ufe0f",
    keyboard: "\u2328\ufe0f",
    computer_mouse: "\ud83d\uddb1\ufe0f",
    trackball: "\ud83d\uddb2\ufe0f",
    minidisc: "\ud83d\udcbd",
    floppy_disk: "\ud83d\udcbe",
    cd: "\ud83d\udcbf",
    dvd: "\ud83d\udcc0",
    abacus: "\ud83e\uddee",
    movie_camera: "\ud83c\udfa5",
    film_strip: "\ud83c\udf9e\ufe0f",
    film_projector: "\ud83d\udcfd\ufe0f",
    clapper: "\ud83c\udfac",
    tv: "\ud83d\udcfa",
    camera: "\ud83d\udcf7",
    camera_flash: "\ud83d\udcf8",
    video_camera: "\ud83d\udcf9",
    vhs: "\ud83d\udcfc",
    mag: "\ud83d\udd0d",
    mag_right: "\ud83d\udd0e",
    candle: "\ud83d\udd6f\ufe0f",
    bulb: "\ud83d\udca1",
    flashlight: "\ud83d\udd26",
    izakaya_lantern: "\ud83c\udfee",
    lantern: "\ud83c\udfee",
    diya_lamp: "\ud83e\ude94",
    notebook_with_decorative_cover: "\ud83d\udcd4",
    closed_book: "\ud83d\udcd5",
    book: "\ud83d\udcd6",
    open_book: "\ud83d\udcd6",
    green_book: "\ud83d\udcd7",
    blue_book: "\ud83d\udcd8",
    orange_book: "\ud83d\udcd9",
    books: "\ud83d\udcda",
    notebook: "\ud83d\udcd3",
    ledger: "\ud83d\udcd2",
    page_with_curl: "\ud83d\udcc3",
    scroll: "\ud83d\udcdc",
    page_facing_up: "\ud83d\udcc4",
    newspaper: "\ud83d\udcf0",
    newspaper_roll: "\ud83d\uddde\ufe0f",
    bookmark_tabs: "\ud83d\udcd1",
    bookmark: "\ud83d\udd16",
    label: "\ud83c\udff7\ufe0f",
    moneybag: "\ud83d\udcb0",
    coin: "\ud83e\ude99",
    yen: "\ud83d\udcb4",
    dollar: "\ud83d\udcb5",
    euro: "\ud83d\udcb6",
    pound: "\ud83d\udcb7",
    money_with_wings: "\ud83d\udcb8",
    credit_card: "\ud83d\udcb3",
    receipt: "\ud83e\uddfe",
    chart: "\ud83d\udcb9",
    envelope: "\u2709\ufe0f",
    email: "\ud83d\udce7",
    "e-mail": "\ud83d\udce7",
    incoming_envelope: "\ud83d\udce8",
    envelope_with_arrow: "\ud83d\udce9",
    outbox_tray: "\ud83d\udce4",
    inbox_tray: "\ud83d\udce5",
    package: "\ud83d\udce6",
    mailbox: "\ud83d\udceb",
    mailbox_closed: "\ud83d\udcea",
    mailbox_with_mail: "\ud83d\udcec",
    mailbox_with_no_mail: "\ud83d\udced",
    postbox: "\ud83d\udcee",
    ballot_box: "\ud83d\uddf3\ufe0f",
    pencil2: "\u270f\ufe0f",
    black_nib: "\u2712\ufe0f",
    fountain_pen: "\ud83d\udd8b\ufe0f",
    pen: "\ud83d\udd8a\ufe0f",
    paintbrush: "\ud83d\udd8c\ufe0f",
    crayon: "\ud83d\udd8d\ufe0f",
    memo: "\ud83d\udcdd",
    pencil: "\ud83d\udcdd",
    briefcase: "\ud83d\udcbc",
    file_folder: "\ud83d\udcc1",
    open_file_folder: "\ud83d\udcc2",
    card_index_dividers: "\ud83d\uddc2\ufe0f",
    date: "\ud83d\udcc5",
    calendar: "\ud83d\udcc6",
    spiral_notepad: "\ud83d\uddd2\ufe0f",
    spiral_calendar: "\ud83d\uddd3\ufe0f",
    card_index: "\ud83d\udcc7",
    chart_with_upwards_trend: "\ud83d\udcc8",
    chart_with_downwards_trend: "\ud83d\udcc9",
    bar_chart: "\ud83d\udcca",
    clipboard: "\ud83d\udccb",
    pushpin: "\ud83d\udccc",
    round_pushpin: "\ud83d\udccd",
    paperclip: "\ud83d\udcce",
    paperclips: "\ud83d\udd87\ufe0f",
    straight_ruler: "\ud83d\udccf",
    triangular_ruler: "\ud83d\udcd0",
    scissors: "\u2702\ufe0f",
    card_file_box: "\ud83d\uddc3\ufe0f",
    file_cabinet: "\ud83d\uddc4\ufe0f",
    wastebasket: "\ud83d\uddd1\ufe0f",
    lock: "\ud83d\udd12",
    unlock: "\ud83d\udd13",
    lock_with_ink_pen: "\ud83d\udd0f",
    closed_lock_with_key: "\ud83d\udd10",
    key: "\ud83d\udd11",
    old_key: "\ud83d\udddd\ufe0f",
    hammer: "\ud83d\udd28",
    axe: "\ud83e\ude93",
    pick: "\u26cf\ufe0f",
    hammer_and_pick: "\u2692\ufe0f",
    hammer_and_wrench: "\ud83d\udee0\ufe0f",
    dagger: "\ud83d\udde1\ufe0f",
    crossed_swords: "\u2694\ufe0f",
    gun: "\ud83d\udd2b",
    boomerang: "\ud83e\ude83",
    bow_and_arrow: "\ud83c\udff9",
    shield: "\ud83d\udee1\ufe0f",
    carpentry_saw: "\ud83e\ude9a",
    wrench: "\ud83d\udd27",
    screwdriver: "\ud83e\ude9b",
    nut_and_bolt: "\ud83d\udd29",
    gear: "\u2699\ufe0f",
    clamp: "\ud83d\udddc\ufe0f",
    balance_scale: "\u2696\ufe0f",
    probing_cane: "\ud83e\uddaf",
    link: "\ud83d\udd17",
    chains: "\u26d3\ufe0f",
    hook: "\ud83e\ude9d",
    toolbox: "\ud83e\uddf0",
    magnet: "\ud83e\uddf2",
    ladder: "\ud83e\ude9c",
    alembic: "\u2697\ufe0f",
    test_tube: "\ud83e\uddea",
    petri_dish: "\ud83e\uddeb",
    dna: "\ud83e\uddec",
    microscope: "\ud83d\udd2c",
    telescope: "\ud83d\udd2d",
    satellite: "\ud83d\udce1",
    syringe: "\ud83d\udc89",
    drop_of_blood: "\ud83e\ude78",
    pill: "\ud83d\udc8a",
    adhesive_bandage: "\ud83e\ude79",
    stethoscope: "\ud83e\ude7a",
    door: "\ud83d\udeaa",
    elevator: "\ud83d\uded7",
    mirror: "\ud83e\ude9e",
    window: "\ud83e\ude9f",
    bed: "\ud83d\udecf\ufe0f",
    couch_and_lamp: "\ud83d\udecb\ufe0f",
    chair: "\ud83e\ude91",
    toilet: "\ud83d\udebd",
    plunger: "\ud83e\udea0",
    shower: "\ud83d\udebf",
    bathtub: "\ud83d\udec1",
    mouse_trap: "\ud83e\udea4",
    razor: "\ud83e\ude92",
    lotion_bottle: "\ud83e\uddf4",
    safety_pin: "\ud83e\uddf7",
    broom: "\ud83e\uddf9",
    basket: "\ud83e\uddfa",
    roll_of_paper: "\ud83e\uddfb",
    bucket: "\ud83e\udea3",
    soap: "\ud83e\uddfc",
    toothbrush: "\ud83e\udea5",
    sponge: "\ud83e\uddfd",
    fire_extinguisher: "\ud83e\uddef",
    shopping_cart: "\ud83d\uded2",
    smoking: "\ud83d\udeac",
    coffin: "\u26b0\ufe0f",
    headstone: "\ud83e\udea6",
    funeral_urn: "\u26b1\ufe0f",
    moyai: "\ud83d\uddff",
    placard: "\ud83e\udea7",
    atm: "\ud83c\udfe7",
    put_litter_in_its_place: "\ud83d\udeae",
    potable_water: "\ud83d\udeb0",
    wheelchair: "\u267f",
    mens: "\ud83d\udeb9",
    womens: "\ud83d\udeba",
    restroom: "\ud83d\udebb",
    baby_symbol: "\ud83d\udebc",
    wc: "\ud83d\udebe",
    passport_control: "\ud83d\udec2",
    customs: "\ud83d\udec3",
    baggage_claim: "\ud83d\udec4",
    left_luggage: "\ud83d\udec5",
    warning: "\u26a0\ufe0f",
    children_crossing: "\ud83d\udeb8",
    no_entry: "\u26d4",
    no_entry_sign: "\ud83d\udeab",
    no_bicycles: "\ud83d\udeb3",
    no_smoking: "\ud83d\udead",
    do_not_litter: "\ud83d\udeaf",
    "non-potable_water": "\ud83d\udeb1",
    no_pedestrians: "\ud83d\udeb7",
    no_mobile_phones: "\ud83d\udcf5",
    underage: "\ud83d\udd1e",
    radioactive: "\u2622\ufe0f",
    biohazard: "\u2623\ufe0f",
    arrow_up: "\u2b06\ufe0f",
    arrow_upper_right: "\u2197\ufe0f",
    arrow_right: "\u27a1\ufe0f",
    arrow_lower_right: "\u2198\ufe0f",
    arrow_down: "\u2b07\ufe0f",
    arrow_lower_left: "\u2199\ufe0f",
    arrow_left: "\u2b05\ufe0f",
    arrow_upper_left: "\u2196\ufe0f",
    arrow_up_down: "\u2195\ufe0f",
    left_right_arrow: "\u2194\ufe0f",
    leftwards_arrow_with_hook: "\u21a9\ufe0f",
    arrow_right_hook: "\u21aa\ufe0f",
    arrow_heading_up: "\u2934\ufe0f",
    arrow_heading_down: "\u2935\ufe0f",
    arrows_clockwise: "\ud83d\udd03",
    arrows_counterclockwise: "\ud83d\udd04",
    back: "\ud83d\udd19",
    end: "\ud83d\udd1a",
    on: "\ud83d\udd1b",
    soon: "\ud83d\udd1c",
    top: "\ud83d\udd1d",
    place_of_worship: "\ud83d\uded0",
    atom_symbol: "\u269b\ufe0f",
    om: "\ud83d\udd49\ufe0f",
    star_of_david: "\u2721\ufe0f",
    wheel_of_dharma: "\u2638\ufe0f",
    yin_yang: "\u262f\ufe0f",
    latin_cross: "\u271d\ufe0f",
    orthodox_cross: "\u2626\ufe0f",
    star_and_crescent: "\u262a\ufe0f",
    peace_symbol: "\u262e\ufe0f",
    menorah: "\ud83d\udd4e",
    six_pointed_star: "\ud83d\udd2f",
    aries: "\u2648",
    taurus: "\u2649",
    gemini: "\u264a",
    cancer: "\u264b",
    leo: "\u264c",
    virgo: "\u264d",
    libra: "\u264e",
    scorpius: "\u264f",
    sagittarius: "\u2650",
    capricorn: "\u2651",
    aquarius: "\u2652",
    pisces: "\u2653",
    ophiuchus: "\u26ce",
    twisted_rightwards_arrows: "\ud83d\udd00",
    repeat: "\ud83d\udd01",
    repeat_one: "\ud83d\udd02",
    arrow_forward: "\u25b6\ufe0f",
    fast_forward: "\u23e9",
    next_track_button: "\u23ed\ufe0f",
    play_or_pause_button: "\u23ef\ufe0f",
    arrow_backward: "\u25c0\ufe0f",
    rewind: "\u23ea",
    previous_track_button: "\u23ee\ufe0f",
    arrow_up_small: "\ud83d\udd3c",
    arrow_double_up: "\u23eb",
    arrow_down_small: "\ud83d\udd3d",
    arrow_double_down: "\u23ec",
    pause_button: "\u23f8\ufe0f",
    stop_button: "\u23f9\ufe0f",
    record_button: "\u23fa\ufe0f",
    eject_button: "\u23cf\ufe0f",
    cinema: "\ud83c\udfa6",
    low_brightness: "\ud83d\udd05",
    high_brightness: "\ud83d\udd06",
    signal_strength: "\ud83d\udcf6",
    vibration_mode: "\ud83d\udcf3",
    mobile_phone_off: "\ud83d\udcf4",
    female_sign: "\u2640\ufe0f",
    male_sign: "\u2642\ufe0f",
    transgender_symbol: "\u26a7\ufe0f",
    heavy_multiplication_x: "\u2716\ufe0f",
    heavy_plus_sign: "\u2795",
    heavy_minus_sign: "\u2796",
    heavy_division_sign: "\u2797",
    infinity: "\u267e\ufe0f",
    bangbang: "\u203c\ufe0f",
    interrobang: "\u2049\ufe0f",
    question: "\u2753",
    grey_question: "\u2754",
    grey_exclamation: "\u2755",
    exclamation: "\u2757",
    heavy_exclamation_mark: "\u2757",
    wavy_dash: "\u3030\ufe0f",
    currency_exchange: "\ud83d\udcb1",
    heavy_dollar_sign: "\ud83d\udcb2",
    medical_symbol: "\u2695\ufe0f",
    recycle: "\u267b\ufe0f",
    fleur_de_lis: "\u269c\ufe0f",
    trident: "\ud83d\udd31",
    name_badge: "\ud83d\udcdb",
    beginner: "\ud83d\udd30",
    o: "\u2b55",
    white_check_mark: "\u2705",
    ballot_box_with_check: "\u2611\ufe0f",
    heavy_check_mark: "\u2714\ufe0f",
    x: "\u274c",
    negative_squared_cross_mark: "\u274e",
    curly_loop: "\u27b0",
    loop: "\u27bf",
    part_alternation_mark: "\u303d\ufe0f",
    eight_spoked_asterisk: "\u2733\ufe0f",
    eight_pointed_black_star: "\u2734\ufe0f",
    sparkle: "\u2747\ufe0f",
    copyright: "\xa9\ufe0f",
    registered: "\xae\ufe0f",
    tm: "\u2122\ufe0f",
    hash: "#\ufe0f\u20e3",
    asterisk: "*\ufe0f\u20e3",
    zero: "0\ufe0f\u20e3",
    one: "1\ufe0f\u20e3",
    two: "2\ufe0f\u20e3",
    three: "3\ufe0f\u20e3",
    four: "4\ufe0f\u20e3",
    five: "5\ufe0f\u20e3",
    six: "6\ufe0f\u20e3",
    seven: "7\ufe0f\u20e3",
    eight: "8\ufe0f\u20e3",
    nine: "9\ufe0f\u20e3",
    keycap_ten: "\ud83d\udd1f",
    capital_abcd: "\ud83d\udd20",
    abcd: "\ud83d\udd21",
    symbols: "\ud83d\udd23",
    abc: "\ud83d\udd24",
    a: "\ud83c\udd70\ufe0f",
    ab: "\ud83c\udd8e",
    b: "\ud83c\udd71\ufe0f",
    cl: "\ud83c\udd91",
    cool: "\ud83c\udd92",
    free: "\ud83c\udd93",
    information_source: "\u2139\ufe0f",
    id: "\ud83c\udd94",
    m: "\u24c2\ufe0f",
    new: "\ud83c\udd95",
    ng: "\ud83c\udd96",
    o2: "\ud83c\udd7e\ufe0f",
    ok: "\ud83c\udd97",
    parking: "\ud83c\udd7f\ufe0f",
    sos: "\ud83c\udd98",
    up: "\ud83c\udd99",
    vs: "\ud83c\udd9a",
    koko: "\ud83c\ude01",
    sa: "\ud83c\ude02\ufe0f",
    ideograph_advantage: "\ud83c\ude50",
    accept: "\ud83c\ude51",
    congratulations: "\u3297\ufe0f",
    secret: "\u3299\ufe0f",
    u6e80: "\ud83c\ude35",
    red_circle: "\ud83d\udd34",
    orange_circle: "\ud83d\udfe0",
    yellow_circle: "\ud83d\udfe1",
    green_circle: "\ud83d\udfe2",
    large_blue_circle: "\ud83d\udd35",
    purple_circle: "\ud83d\udfe3",
    brown_circle: "\ud83d\udfe4",
    black_circle: "\u26ab",
    white_circle: "\u26aa",
    red_square: "\ud83d\udfe5",
    orange_square: "\ud83d\udfe7",
    yellow_square: "\ud83d\udfe8",
    green_square: "\ud83d\udfe9",
    blue_square: "\ud83d\udfe6",
    purple_square: "\ud83d\udfea",
    brown_square: "\ud83d\udfeb",
    black_large_square: "\u2b1b",
    white_large_square: "\u2b1c",
    black_medium_square: "\u25fc\ufe0f",
    white_medium_square: "\u25fb\ufe0f",
    black_medium_small_square: "\u25fe",
    white_medium_small_square: "\u25fd",
    black_small_square: "\u25aa\ufe0f",
    white_small_square: "\u25ab\ufe0f",
    large_orange_diamond: "\ud83d\udd36",
    large_blue_diamond: "\ud83d\udd37",
    small_orange_diamond: "\ud83d\udd38",
    small_blue_diamond: "\ud83d\udd39",
    small_red_triangle: "\ud83d\udd3a",
    small_red_triangle_down: "\ud83d\udd3b",
    diamond_shape_with_a_dot_inside: "\ud83d\udca0",
    radio_button: "\ud83d\udd18",
    white_square_button: "\ud83d\udd33",
    black_square_button: "\ud83d\udd32",
    checkered_flag: "\ud83c\udfc1",
    triangular_flag_on_post: "\ud83d\udea9",
    crossed_flags: "\ud83c\udf8c",
    black_flag: "\ud83c\udff4",
    white_flag: "\ud83c\udff3\ufe0f",
    rainbow_flag: "\ud83c\udff3\ufe0f\u200d\ud83c\udf08",
    transgender_flag: "\ud83c\udff3\ufe0f\u200d\u26a7\ufe0f",
    pirate_flag: "\ud83c\udff4\u200d\u2620\ufe0f",
    ascension_island: "\ud83c\udde6\ud83c\udde8",
    andorra: "\ud83c\udde6\ud83c\udde9",
    united_arab_emirates: "\ud83c\udde6\ud83c\uddea",
    afghanistan: "\ud83c\udde6\ud83c\uddeb",
    antigua_barbuda: "\ud83c\udde6\ud83c\uddec",
    anguilla: "\ud83c\udde6\ud83c\uddee",
    albania: "\ud83c\udde6\ud83c\uddf1",
    armenia: "\ud83c\udde6\ud83c\uddf2",
    angola: "\ud83c\udde6\ud83c\uddf4",
    antarctica: "\ud83c\udde6\ud83c\uddf6",
    argentina: "\ud83c\udde6\ud83c\uddf7",
    american_samoa: "\ud83c\udde6\ud83c\uddf8",
    austria: "\ud83c\udde6\ud83c\uddf9",
    australia: "\ud83c\udde6\ud83c\uddfa",
    aruba: "\ud83c\udde6\ud83c\uddfc",
    aland_islands: "\ud83c\udde6\ud83c\uddfd",
    azerbaijan: "\ud83c\udde6\ud83c\uddff",
    bosnia_herzegovina: "\ud83c\udde7\ud83c\udde6",
    barbados: "\ud83c\udde7\ud83c\udde7",
    bangladesh: "\ud83c\udde7\ud83c\udde9",
    belgium: "\ud83c\udde7\ud83c\uddea",
    burkina_faso: "\ud83c\udde7\ud83c\uddeb",
    bulgaria: "\ud83c\udde7\ud83c\uddec",
    bahrain: "\ud83c\udde7\ud83c\udded",
    burundi: "\ud83c\udde7\ud83c\uddee",
    benin: "\ud83c\udde7\ud83c\uddef",
    st_barthelemy: "\ud83c\udde7\ud83c\uddf1",
    bermuda: "\ud83c\udde7\ud83c\uddf2",
    brunei: "\ud83c\udde7\ud83c\uddf3",
    bolivia: "\ud83c\udde7\ud83c\uddf4",
    caribbean_netherlands: "\ud83c\udde7\ud83c\uddf6",
    brazil: "\ud83c\udde7\ud83c\uddf7",
    bahamas: "\ud83c\udde7\ud83c\uddf8",
    bhutan: "\ud83c\udde7\ud83c\uddf9",
    bouvet_island: "\ud83c\udde7\ud83c\uddfb",
    botswana: "\ud83c\udde7\ud83c\uddfc",
    belarus: "\ud83c\udde7\ud83c\uddfe",
    belize: "\ud83c\udde7\ud83c\uddff",
    canada: "\ud83c\udde8\ud83c\udde6",
    cocos_islands: "\ud83c\udde8\ud83c\udde8",
    congo_kinshasa: "\ud83c\udde8\ud83c\udde9",
    central_african_republic: "\ud83c\udde8\ud83c\uddeb",
    congo_brazzaville: "\ud83c\udde8\ud83c\uddec",
    switzerland: "\ud83c\udde8\ud83c\udded",
    cote_divoire: "\ud83c\udde8\ud83c\uddee",
    cook_islands: "\ud83c\udde8\ud83c\uddf0",
    chile: "\ud83c\udde8\ud83c\uddf1",
    cameroon: "\ud83c\udde8\ud83c\uddf2",
    cn: "\ud83c\udde8\ud83c\uddf3",
    colombia: "\ud83c\udde8\ud83c\uddf4",
    clipperton_island: "\ud83c\udde8\ud83c\uddf5",
    costa_rica: "\ud83c\udde8\ud83c\uddf7",
    cuba: "\ud83c\udde8\ud83c\uddfa",
    cape_verde: "\ud83c\udde8\ud83c\uddfb",
    curacao: "\ud83c\udde8\ud83c\uddfc",
    christmas_island: "\ud83c\udde8\ud83c\uddfd",
    cyprus: "\ud83c\udde8\ud83c\uddfe",
    czech_republic: "\ud83c\udde8\ud83c\uddff",
    de: "\ud83c\udde9\ud83c\uddea",
    diego_garcia: "\ud83c\udde9\ud83c\uddec",
    djibouti: "\ud83c\udde9\ud83c\uddef",
    denmark: "\ud83c\udde9\ud83c\uddf0",
    dominica: "\ud83c\udde9\ud83c\uddf2",
    dominican_republic: "\ud83c\udde9\ud83c\uddf4",
    algeria: "\ud83c\udde9\ud83c\uddff",
    ceuta_melilla: "\ud83c\uddea\ud83c\udde6",
    ecuador: "\ud83c\uddea\ud83c\udde8",
    estonia: "\ud83c\uddea\ud83c\uddea",
    egypt: "\ud83c\uddea\ud83c\uddec",
    western_sahara: "\ud83c\uddea\ud83c\udded",
    eritrea: "\ud83c\uddea\ud83c\uddf7",
    es: "\ud83c\uddea\ud83c\uddf8",
    ethiopia: "\ud83c\uddea\ud83c\uddf9",
    eu: "\ud83c\uddea\ud83c\uddfa",
    european_union: "\ud83c\uddea\ud83c\uddfa",
    finland: "\ud83c\uddeb\ud83c\uddee",
    fiji: "\ud83c\uddeb\ud83c\uddef",
    falkland_islands: "\ud83c\uddeb\ud83c\uddf0",
    micronesia: "\ud83c\uddeb\ud83c\uddf2",
    faroe_islands: "\ud83c\uddeb\ud83c\uddf4",
    fr: "\ud83c\uddeb\ud83c\uddf7",
    gabon: "\ud83c\uddec\ud83c\udde6",
    gb: "\ud83c\uddec\ud83c\udde7",
    uk: "\ud83c\uddec\ud83c\udde7",
    grenada: "\ud83c\uddec\ud83c\udde9",
    georgia: "\ud83c\uddec\ud83c\uddea",
    french_guiana: "\ud83c\uddec\ud83c\uddeb",
    guernsey: "\ud83c\uddec\ud83c\uddec",
    ghana: "\ud83c\uddec\ud83c\udded",
    gibraltar: "\ud83c\uddec\ud83c\uddee",
    greenland: "\ud83c\uddec\ud83c\uddf1",
    gambia: "\ud83c\uddec\ud83c\uddf2",
    guinea: "\ud83c\uddec\ud83c\uddf3",
    guadeloupe: "\ud83c\uddec\ud83c\uddf5",
    equatorial_guinea: "\ud83c\uddec\ud83c\uddf6",
    greece: "\ud83c\uddec\ud83c\uddf7",
    south_georgia_south_sandwich_islands: "\ud83c\uddec\ud83c\uddf8",
    guatemala: "\ud83c\uddec\ud83c\uddf9",
    guam: "\ud83c\uddec\ud83c\uddfa",
    guinea_bissau: "\ud83c\uddec\ud83c\uddfc",
    guyana: "\ud83c\uddec\ud83c\uddfe",
    hong_kong: "\ud83c\udded\ud83c\uddf0",
    heard_mcdonald_islands: "\ud83c\udded\ud83c\uddf2",
    honduras: "\ud83c\udded\ud83c\uddf3",
    croatia: "\ud83c\udded\ud83c\uddf7",
    haiti: "\ud83c\udded\ud83c\uddf9",
    hungary: "\ud83c\udded\ud83c\uddfa",
    canary_islands: "\ud83c\uddee\ud83c\udde8",
    indonesia: "\ud83c\uddee\ud83c\udde9",
    ireland: "\ud83c\uddee\ud83c\uddea",
    israel: "\ud83c\uddee\ud83c\uddf1",
    isle_of_man: "\ud83c\uddee\ud83c\uddf2",
    india: "\ud83c\uddee\ud83c\uddf3",
    british_indian_ocean_territory: "\ud83c\uddee\ud83c\uddf4",
    iraq: "\ud83c\uddee\ud83c\uddf6",
    iran: "\ud83c\uddee\ud83c\uddf7",
    iceland: "\ud83c\uddee\ud83c\uddf8",
    it: "\ud83c\uddee\ud83c\uddf9",
    jersey: "\ud83c\uddef\ud83c\uddea",
    jamaica: "\ud83c\uddef\ud83c\uddf2",
    jordan: "\ud83c\uddef\ud83c\uddf4",
    jp: "\ud83c\uddef\ud83c\uddf5",
    kenya: "\ud83c\uddf0\ud83c\uddea",
    kyrgyzstan: "\ud83c\uddf0\ud83c\uddec",
    cambodia: "\ud83c\uddf0\ud83c\udded",
    kiribati: "\ud83c\uddf0\ud83c\uddee",
    comoros: "\ud83c\uddf0\ud83c\uddf2",
    st_kitts_nevis: "\ud83c\uddf0\ud83c\uddf3",
    north_korea: "\ud83c\uddf0\ud83c\uddf5",
    kr: "\ud83c\uddf0\ud83c\uddf7",
    kuwait: "\ud83c\uddf0\ud83c\uddfc",
    cayman_islands: "\ud83c\uddf0\ud83c\uddfe",
    kazakhstan: "\ud83c\uddf0\ud83c\uddff",
    laos: "\ud83c\uddf1\ud83c\udde6",
    lebanon: "\ud83c\uddf1\ud83c\udde7",
    st_lucia: "\ud83c\uddf1\ud83c\udde8",
    liechtenstein: "\ud83c\uddf1\ud83c\uddee",
    sri_lanka: "\ud83c\uddf1\ud83c\uddf0",
    liberia: "\ud83c\uddf1\ud83c\uddf7",
    lesotho: "\ud83c\uddf1\ud83c\uddf8",
    lithuania: "\ud83c\uddf1\ud83c\uddf9",
    luxembourg: "\ud83c\uddf1\ud83c\uddfa",
    latvia: "\ud83c\uddf1\ud83c\uddfb",
    libya: "\ud83c\uddf1\ud83c\uddfe",
    morocco: "\ud83c\uddf2\ud83c\udde6",
    monaco: "\ud83c\uddf2\ud83c\udde8",
    moldova: "\ud83c\uddf2\ud83c\udde9",
    montenegro: "\ud83c\uddf2\ud83c\uddea",
    st_martin: "\ud83c\uddf2\ud83c\uddeb",
    madagascar: "\ud83c\uddf2\ud83c\uddec",
    marshall_islands: "\ud83c\uddf2\ud83c\udded",
    macedonia: "\ud83c\uddf2\ud83c\uddf0",
    mali: "\ud83c\uddf2\ud83c\uddf1",
    myanmar: "\ud83c\uddf2\ud83c\uddf2",
    mongolia: "\ud83c\uddf2\ud83c\uddf3",
    macau: "\ud83c\uddf2\ud83c\uddf4",
    northern_mariana_islands: "\ud83c\uddf2\ud83c\uddf5",
    martinique: "\ud83c\uddf2\ud83c\uddf6",
    mauritania: "\ud83c\uddf2\ud83c\uddf7",
    montserrat: "\ud83c\uddf2\ud83c\uddf8",
    malta: "\ud83c\uddf2\ud83c\uddf9",
    mauritius: "\ud83c\uddf2\ud83c\uddfa",
    maldives: "\ud83c\uddf2\ud83c\uddfb",
    malawi: "\ud83c\uddf2\ud83c\uddfc",
    mexico: "\ud83c\uddf2\ud83c\uddfd",
    malaysia: "\ud83c\uddf2\ud83c\uddfe",
    mozambique: "\ud83c\uddf2\ud83c\uddff",
    namibia: "\ud83c\uddf3\ud83c\udde6",
    new_caledonia: "\ud83c\uddf3\ud83c\udde8",
    niger: "\ud83c\uddf3\ud83c\uddea",
    norfolk_island: "\ud83c\uddf3\ud83c\uddeb",
    nigeria: "\ud83c\uddf3\ud83c\uddec",
    nicaragua: "\ud83c\uddf3\ud83c\uddee",
    netherlands: "\ud83c\uddf3\ud83c\uddf1",
    norway: "\ud83c\uddf3\ud83c\uddf4",
    nepal: "\ud83c\uddf3\ud83c\uddf5",
    nauru: "\ud83c\uddf3\ud83c\uddf7",
    niue: "\ud83c\uddf3\ud83c\uddfa",
    new_zealand: "\ud83c\uddf3\ud83c\uddff",
    oman: "\ud83c\uddf4\ud83c\uddf2",
    panama: "\ud83c\uddf5\ud83c\udde6",
    peru: "\ud83c\uddf5\ud83c\uddea",
    french_polynesia: "\ud83c\uddf5\ud83c\uddeb",
    papua_new_guinea: "\ud83c\uddf5\ud83c\uddec",
    philippines: "\ud83c\uddf5\ud83c\udded",
    pakistan: "\ud83c\uddf5\ud83c\uddf0",
    poland: "\ud83c\uddf5\ud83c\uddf1",
    st_pierre_miquelon: "\ud83c\uddf5\ud83c\uddf2",
    pitcairn_islands: "\ud83c\uddf5\ud83c\uddf3",
    puerto_rico: "\ud83c\uddf5\ud83c\uddf7",
    palestinian_territories: "\ud83c\uddf5\ud83c\uddf8",
    portugal: "\ud83c\uddf5\ud83c\uddf9",
    palau: "\ud83c\uddf5\ud83c\uddfc",
    paraguay: "\ud83c\uddf5\ud83c\uddfe",
    qatar: "\ud83c\uddf6\ud83c\udde6",
    reunion: "\ud83c\uddf7\ud83c\uddea",
    romania: "\ud83c\uddf7\ud83c\uddf4",
    serbia: "\ud83c\uddf7\ud83c\uddf8",
    ru: "\ud83c\uddf7\ud83c\uddfa",
    rwanda: "\ud83c\uddf7\ud83c\uddfc",
    saudi_arabia: "\ud83c\uddf8\ud83c\udde6",
    solomon_islands: "\ud83c\uddf8\ud83c\udde7",
    seychelles: "\ud83c\uddf8\ud83c\udde8",
    sudan: "\ud83c\uddf8\ud83c\udde9",
    sweden: "\ud83c\uddf8\ud83c\uddea",
    singapore: "\ud83c\uddf8\ud83c\uddec",
    st_helena: "\ud83c\uddf8\ud83c\udded",
    slovenia: "\ud83c\uddf8\ud83c\uddee",
    svalbard_jan_mayen: "\ud83c\uddf8\ud83c\uddef",
    slovakia: "\ud83c\uddf8\ud83c\uddf0",
    sierra_leone: "\ud83c\uddf8\ud83c\uddf1",
    san_marino: "\ud83c\uddf8\ud83c\uddf2",
    senegal: "\ud83c\uddf8\ud83c\uddf3",
    somalia: "\ud83c\uddf8\ud83c\uddf4",
    suriname: "\ud83c\uddf8\ud83c\uddf7",
    south_sudan: "\ud83c\uddf8\ud83c\uddf8",
    sao_tome_principe: "\ud83c\uddf8\ud83c\uddf9",
    el_salvador: "\ud83c\uddf8\ud83c\uddfb",
    sint_maarten: "\ud83c\uddf8\ud83c\uddfd",
    syria: "\ud83c\uddf8\ud83c\uddfe",
    swaziland: "\ud83c\uddf8\ud83c\uddff",
    tristan_da_cunha: "\ud83c\uddf9\ud83c\udde6",
    turks_caicos_islands: "\ud83c\uddf9\ud83c\udde8",
    chad: "\ud83c\uddf9\ud83c\udde9",
    french_southern_territories: "\ud83c\uddf9\ud83c\uddeb",
    togo: "\ud83c\uddf9\ud83c\uddec",
    thailand: "\ud83c\uddf9\ud83c\udded",
    tajikistan: "\ud83c\uddf9\ud83c\uddef",
    tokelau: "\ud83c\uddf9\ud83c\uddf0",
    timor_leste: "\ud83c\uddf9\ud83c\uddf1",
    turkmenistan: "\ud83c\uddf9\ud83c\uddf2",
    tunisia: "\ud83c\uddf9\ud83c\uddf3",
    tonga: "\ud83c\uddf9\ud83c\uddf4",
    tr: "\ud83c\uddf9\ud83c\uddf7",
    trinidad_tobago: "\ud83c\uddf9\ud83c\uddf9",
    tuvalu: "\ud83c\uddf9\ud83c\uddfb",
    taiwan: "\ud83c\uddf9\ud83c\uddfc",
    tanzania: "\ud83c\uddf9\ud83c\uddff",
    ukraine: "\ud83c\uddfa\ud83c\udde6",
    uganda: "\ud83c\uddfa\ud83c\uddec",
    us_outlying_islands: "\ud83c\uddfa\ud83c\uddf2",
    united_nations: "\ud83c\uddfa\ud83c\uddf3",
    us: "\ud83c\uddfa\ud83c\uddf8",
    uruguay: "\ud83c\uddfa\ud83c\uddfe",
    uzbekistan: "\ud83c\uddfa\ud83c\uddff",
    vatican_city: "\ud83c\uddfb\ud83c\udde6",
    st_vincent_grenadines: "\ud83c\uddfb\ud83c\udde8",
    venezuela: "\ud83c\uddfb\ud83c\uddea",
    british_virgin_islands: "\ud83c\uddfb\ud83c\uddec",
    us_virgin_islands: "\ud83c\uddfb\ud83c\uddee",
    vietnam: "\ud83c\uddfb\ud83c\uddf3",
    vanuatu: "\ud83c\uddfb\ud83c\uddfa",
    wallis_futuna: "\ud83c\uddfc\ud83c\uddeb",
    samoa: "\ud83c\uddfc\ud83c\uddf8",
    kosovo: "\ud83c\uddfd\ud83c\uddf0",
    yemen: "\ud83c\uddfe\ud83c\uddea",
    mayotte: "\ud83c\uddfe\ud83c\uddf9",
    south_africa: "\ud83c\uddff\ud83c\udde6",
    zambia: "\ud83c\uddff\ud83c\uddf2",
    zimbabwe: "\ud83c\uddff\ud83c\uddfc",
    england: "\ud83c\udff4\udb40\udc67\udb40\udc62\udb40\udc65\udb40\udc6e\udb40\udc67\udb40\udc7f",
    scotland: "\ud83c\udff4\udb40\udc67\udb40\udc62\udb40\udc73\udb40\udc63\udb40\udc74\udb40\udc7f",
    wales: "\ud83c\udff4\udb40\udc67\udb40\udc62\udb40\udc77\udb40\udc6c\udb40\udc73\udb40\udc7f"
  };
  // Emoticons -> Emoji mapping.
    var shortcuts = {
    angry: [ ">:(", ">:-(" ],
    blush: [ ':")', ':-")' ],
    broken_heart: [ "</3", "<\\3" ],
    // :\ and :-\ not used because of conflict with markdown escaping
    confused: [ ":/", ":-/" ],
    // twemoji shows question
    cry: [ ":'(", ":'-(", ":,(", ":,-(" ],
    frowning: [ ":(", ":-(" ],
    heart: [ "<3" ],
    imp: [ "]:(", "]:-(" ],
    innocent: [ "o:)", "O:)", "o:-)", "O:-)", "0:)", "0:-)" ],
    joy: [ ":')", ":'-)", ":,)", ":,-)", ":'D", ":'-D", ":,D", ":,-D" ],
    kissing: [ ":*", ":-*" ],
    laughing: [ "x-)", "X-)" ],
    neutral_face: [ ":|", ":-|" ],
    open_mouth: [ ":o", ":-o", ":O", ":-O" ],
    rage: [ ":@", ":-@" ],
    smile: [ ":D", ":-D" ],
    smiley: [ ":)", ":-)" ],
    smiling_imp: [ "]:)", "]:-)" ],
    sob: [ ":,'(", ":,'-(", ";(", ";-(" ],
    stuck_out_tongue: [ ":P", ":-P" ],
    sunglasses: [ "8-)", "B-)" ],
    sweat: [ ",:(", ",:-(" ],
    sweat_smile: [ ",:)", ",:-)" ],
    unamused: [ ":s", ":-S", ":z", ":-Z", ":$", ":-$" ],
    wink: [ ";)", ";-)" ]
  };
  var render = function emoji_html(tokens, idx /*, options, env */) {
    return tokens[idx].content;
  };
  // Emojies & shortcuts replacement logic.
    var replace = function create_rule(md, emojies, shortcuts, scanRE, replaceRE) {
    var arrayReplaceAt = md.utils.arrayReplaceAt, ucm = md.utils.lib.ucmicro, ZPCc = new RegExp([ ucm.Z.source, ucm.P.source, ucm.Cc.source ].join("|"));
    function splitTextToken(text, level, Token) {
      var token, last_pos = 0, nodes = [];
      text.replace(replaceRE, (function(match, offset, src) {
        var emoji_name;
        // Validate emoji name
                if (shortcuts.hasOwnProperty(match)) {
          // replace shortcut with full name
          emoji_name = shortcuts[match];
          // Don't allow letters before any shortcut (as in no ":/" in http://)
                    if (offset > 0 && !ZPCc.test(src[offset - 1])) {
            return;
          }
          // Don't allow letters after any shortcut
                    if (offset + match.length < src.length && !ZPCc.test(src[offset + match.length])) {
            return;
          }
        } else {
          emoji_name = match.slice(1, -1);
        }
        // Add new tokens to pending list
                if (offset > last_pos) {
          token = new Token("text", "", 0);
          token.content = text.slice(last_pos, offset);
          nodes.push(token);
        }
        token = new Token("emoji", "", 0);
        token.markup = emoji_name;
        token.content = emojies[emoji_name];
        nodes.push(token);
        last_pos = offset + match.length;
      }));
      if (last_pos < text.length) {
        token = new Token("text", "", 0);
        token.content = text.slice(last_pos);
        nodes.push(token);
      }
      return nodes;
    }
    return function emoji_replace(state) {
      var i, j, l, tokens, token, blockTokens = state.tokens, autolinkLevel = 0;
      for (j = 0, l = blockTokens.length; j < l; j++) {
        if (blockTokens[j].type !== "inline") {
          continue;
        }
        tokens = blockTokens[j].children;
        // We scan from the end, to keep position when new tags added.
        // Use reversed logic in links start/end match
                for (i = tokens.length - 1; i >= 0; i--) {
          token = tokens[i];
          if (token.type === "link_open" || token.type === "link_close") {
            if (token.info === "auto") {
              autolinkLevel -= token.nesting;
            }
          }
          if (token.type === "text" && autolinkLevel === 0 && scanRE.test(token.content)) {
            // replace current node
            blockTokens[j].children = tokens = arrayReplaceAt(tokens, i, splitTextToken(token.content, token.level, state.Token));
          }
        }
      }
    };
  };
  // Convert input options to more useable format
    function quoteRE(str) {
    return str.replace(/[.?*+^$[\]\\(){}|-]/g, "\\$&");
  }
  var normalize_opts = function normalize_opts(options) {
    var emojies = options.defs, shortcuts;
    // Filter emojies by whitelist, if needed
        if (options.enabled.length) {
      emojies = Object.keys(emojies).reduce((function(acc, key) {
        if (options.enabled.indexOf(key) >= 0) {
          acc[key] = emojies[key];
        }
        return acc;
      }), {});
    }
    // Flatten shortcuts to simple object: { alias: emoji_name }
        shortcuts = Object.keys(options.shortcuts).reduce((function(acc, key) {
      // Skip aliases for filtered emojies, to reduce regexp
      if (!emojies[key]) {
        return acc;
      }
      if (Array.isArray(options.shortcuts[key])) {
        options.shortcuts[key].forEach((function(alias) {
          acc[alias] = key;
        }));
        return acc;
      }
      acc[options.shortcuts[key]] = key;
      return acc;
    }), {});
    var keys = Object.keys(emojies), names;
    // If no definitions are given, return empty regex to avoid replacements with 'undefined'.
        if (keys.length === 0) {
      names = "^$";
    } else {
      // Compile regexp
      names = keys.map((function(name) {
        return ":" + name + ":";
      })).concat(Object.keys(shortcuts)).sort().reverse().map((function(name) {
        return quoteRE(name);
      })).join("|");
    }
    var scanRE = RegExp(names);
    var replaceRE = RegExp(names, "g");
    return {
      defs: emojies,
      shortcuts: shortcuts,
      scanRE: scanRE,
      replaceRE: replaceRE
    };
  };
  var bare = function emoji_plugin(md, options) {
    var defaults = {
      defs: {},
      shortcuts: {},
      enabled: []
    };
    var opts = normalize_opts(md.utils.assign({}, defaults, options || {}));
    md.renderer.rules.emoji = render;
    md.core.ruler.push("emoji", replace(md, opts.defs, opts.shortcuts, opts.scanRE, opts.replaceRE));
  };
  var markdownItEmoji = function emoji_plugin(md, options) {
    var defaults = {
      defs: emojies_defs,
      shortcuts: shortcuts,
      enabled: []
    };
    var opts = md.utils.assign({}, defaults, options || {});
    bare(md, opts);
  };
  // Process footnotes
  ////////////////////////////////////////////////////////////////////////////////
  // Renderer partials
    function render_footnote_anchor_name(tokens, idx, options, env /*, slf*/) {
    var n = Number(tokens[idx].meta.id + 1).toString();
    var prefix = "";
    if (typeof env.docId === "string") {
      prefix = "-" + env.docId + "-";
    }
    return prefix + n;
  }
  function render_footnote_caption(tokens, idx /*, options, env, slf*/) {
    var n = Number(tokens[idx].meta.id + 1).toString();
    if (tokens[idx].meta.subId > 0) {
      n += ":" + tokens[idx].meta.subId;
    }
    return "[" + n + "]";
  }
  function render_footnote_ref(tokens, idx, options, env, slf) {
    var id = slf.rules.footnote_anchor_name(tokens, idx, options, env, slf);
    var caption = slf.rules.footnote_caption(tokens, idx, options, env, slf);
    var refid = id;
    if (tokens[idx].meta.subId > 0) {
      refid += ":" + tokens[idx].meta.subId;
    }
    return '<sup class="footnote-ref"><a href="#fn' + id + '" id="fnref' + refid + '">' + caption + "</a></sup>";
  }
  function render_footnote_block_open(tokens, idx, options) {
    return (options.xhtmlOut ? '<hr class="footnotes-sep" />\n' : '<hr class="footnotes-sep">\n') + '<section class="footnotes">\n' + '<ol class="footnotes-list">\n';
  }
  function render_footnote_block_close() {
    return "</ol>\n</section>\n";
  }
  function render_footnote_open(tokens, idx, options, env, slf) {
    var id = slf.rules.footnote_anchor_name(tokens, idx, options, env, slf);
    if (tokens[idx].meta.subId > 0) {
      id += ":" + tokens[idx].meta.subId;
    }
    return '<li id="fn' + id + '" class="footnote-item">';
  }
  function render_footnote_close() {
    return "</li>\n";
  }
  function render_footnote_anchor(tokens, idx, options, env, slf) {
    var id = slf.rules.footnote_anchor_name(tokens, idx, options, env, slf);
    if (tokens[idx].meta.subId > 0) {
      id += ":" + tokens[idx].meta.subId;
    }
    /* ↩ with escape code to prevent display as Apple Emoji on iOS */    return ' <a href="#fnref' + id + '" class="footnote-backref">\u21a9\ufe0e</a>';
  }
  var markdownItFootnote = function footnote_plugin(md) {
    var parseLinkLabel = md.helpers.parseLinkLabel, isSpace = md.utils.isSpace;
    md.renderer.rules.footnote_ref = render_footnote_ref;
    md.renderer.rules.footnote_block_open = render_footnote_block_open;
    md.renderer.rules.footnote_block_close = render_footnote_block_close;
    md.renderer.rules.footnote_open = render_footnote_open;
    md.renderer.rules.footnote_close = render_footnote_close;
    md.renderer.rules.footnote_anchor = render_footnote_anchor;
    // helpers (only used in other rules, no tokens are attached to those)
        md.renderer.rules.footnote_caption = render_footnote_caption;
    md.renderer.rules.footnote_anchor_name = render_footnote_anchor_name;
    // Process footnote block definition
        function footnote_def(state, startLine, endLine, silent) {
      var oldBMark, oldTShift, oldSCount, oldParentType, pos, label, token, initial, offset, ch, posAfterColon, start = state.bMarks[startLine] + state.tShift[startLine], max = state.eMarks[startLine];
      // line should be at least 5 chars - "[^x]:"
            if (start + 4 > max) {
        return false;
      }
      if (state.src.charCodeAt(start) !== 91 /* [ */) {
        return false;
      }
      if (state.src.charCodeAt(start + 1) !== 94 /* ^ */) {
        return false;
      }
      for (pos = start + 2; pos < max; pos++) {
        if (state.src.charCodeAt(pos) === 32) {
          return false;
        }
        if (state.src.charCodeAt(pos) === 93 /* ] */) {
          break;
        }
      }
      if (pos === start + 2) {
        return false;
      }
 // no empty footnote labels
            if (pos + 1 >= max || state.src.charCodeAt(++pos) !== 58 /* : */) {
        return false;
      }
      if (silent) {
        return true;
      }
      pos++;
      if (!state.env.footnotes) {
        state.env.footnotes = {};
      }
      if (!state.env.footnotes.refs) {
        state.env.footnotes.refs = {};
      }
      label = state.src.slice(start + 2, pos - 2);
      state.env.footnotes.refs[":" + label] = -1;
      token = new state.Token("footnote_reference_open", "", 1);
      token.meta = {
        label: label
      };
      token.level = state.level++;
      state.tokens.push(token);
      oldBMark = state.bMarks[startLine];
      oldTShift = state.tShift[startLine];
      oldSCount = state.sCount[startLine];
      oldParentType = state.parentType;
      posAfterColon = pos;
      initial = offset = state.sCount[startLine] + pos - (state.bMarks[startLine] + state.tShift[startLine]);
      while (pos < max) {
        ch = state.src.charCodeAt(pos);
        if (isSpace(ch)) {
          if (ch === 9) {
            offset += 4 - offset % 4;
          } else {
            offset++;
          }
        } else {
          break;
        }
        pos++;
      }
      state.tShift[startLine] = pos - posAfterColon;
      state.sCount[startLine] = offset - initial;
      state.bMarks[startLine] = posAfterColon;
      state.blkIndent += 4;
      state.parentType = "footnote";
      if (state.sCount[startLine] < state.blkIndent) {
        state.sCount[startLine] += state.blkIndent;
      }
      state.md.block.tokenize(state, startLine, endLine, true);
      state.parentType = oldParentType;
      state.blkIndent -= 4;
      state.tShift[startLine] = oldTShift;
      state.sCount[startLine] = oldSCount;
      state.bMarks[startLine] = oldBMark;
      token = new state.Token("footnote_reference_close", "", -1);
      token.level = --state.level;
      state.tokens.push(token);
      return true;
    }
    // Process inline footnotes (^[...])
        function footnote_inline(state, silent) {
      var labelStart, labelEnd, footnoteId, token, tokens, max = state.posMax, start = state.pos;
      if (start + 2 >= max) {
        return false;
      }
      if (state.src.charCodeAt(start) !== 94 /* ^ */) {
        return false;
      }
      if (state.src.charCodeAt(start + 1) !== 91 /* [ */) {
        return false;
      }
      labelStart = start + 2;
      labelEnd = parseLinkLabel(state, start + 1);
      // parser failed to find ']', so it's not a valid note
            if (labelEnd < 0) {
        return false;
      }
      // We found the end of the link, and know for a fact it's a valid link;
      // so all that's left to do is to call tokenizer.
      
            if (!silent) {
        if (!state.env.footnotes) {
          state.env.footnotes = {};
        }
        if (!state.env.footnotes.list) {
          state.env.footnotes.list = [];
        }
        footnoteId = state.env.footnotes.list.length;
        state.md.inline.parse(state.src.slice(labelStart, labelEnd), state.md, state.env, tokens = []);
        token = state.push("footnote_ref", "", 0);
        token.meta = {
          id: footnoteId
        };
        state.env.footnotes.list[footnoteId] = {
          content: state.src.slice(labelStart, labelEnd),
          tokens: tokens
        };
      }
      state.pos = labelEnd + 1;
      state.posMax = max;
      return true;
    }
    // Process footnote references ([^...])
        function footnote_ref(state, silent) {
      var label, pos, footnoteId, footnoteSubId, token, max = state.posMax, start = state.pos;
      // should be at least 4 chars - "[^x]"
            if (start + 3 > max) {
        return false;
      }
      if (!state.env.footnotes || !state.env.footnotes.refs) {
        return false;
      }
      if (state.src.charCodeAt(start) !== 91 /* [ */) {
        return false;
      }
      if (state.src.charCodeAt(start + 1) !== 94 /* ^ */) {
        return false;
      }
      for (pos = start + 2; pos < max; pos++) {
        if (state.src.charCodeAt(pos) === 32) {
          return false;
        }
        if (state.src.charCodeAt(pos) === 10) {
          return false;
        }
        if (state.src.charCodeAt(pos) === 93 /* ] */) {
          break;
        }
      }
      if (pos === start + 2) {
        return false;
      }
 // no empty footnote labels
            if (pos >= max) {
        return false;
      }
      pos++;
      label = state.src.slice(start + 2, pos - 1);
      if (typeof state.env.footnotes.refs[":" + label] === "undefined") {
        return false;
      }
      if (!silent) {
        if (!state.env.footnotes.list) {
          state.env.footnotes.list = [];
        }
        if (state.env.footnotes.refs[":" + label] < 0) {
          footnoteId = state.env.footnotes.list.length;
          state.env.footnotes.list[footnoteId] = {
            label: label,
            count: 0
          };
          state.env.footnotes.refs[":" + label] = footnoteId;
        } else {
          footnoteId = state.env.footnotes.refs[":" + label];
        }
        footnoteSubId = state.env.footnotes.list[footnoteId].count;
        state.env.footnotes.list[footnoteId].count++;
        token = state.push("footnote_ref", "", 0);
        token.meta = {
          id: footnoteId,
          subId: footnoteSubId,
          label: label
        };
      }
      state.pos = pos;
      state.posMax = max;
      return true;
    }
    // Glue footnote tokens to end of token stream
        function footnote_tail(state) {
      var i, l, j, t, lastParagraph, list, token, tokens, current, currentLabel, insideRef = false, refTokens = {};
      if (!state.env.footnotes) {
        return;
      }
      state.tokens = state.tokens.filter((function(tok) {
        if (tok.type === "footnote_reference_open") {
          insideRef = true;
          current = [];
          currentLabel = tok.meta.label;
          return false;
        }
        if (tok.type === "footnote_reference_close") {
          insideRef = false;
          // prepend ':' to avoid conflict with Object.prototype members
                    refTokens[":" + currentLabel] = current;
          return false;
        }
        if (insideRef) {
          current.push(tok);
        }
        return !insideRef;
      }));
      if (!state.env.footnotes.list) {
        return;
      }
      list = state.env.footnotes.list;
      token = new state.Token("footnote_block_open", "", 1);
      state.tokens.push(token);
      for (i = 0, l = list.length; i < l; i++) {
        token = new state.Token("footnote_open", "", 1);
        token.meta = {
          id: i,
          label: list[i].label
        };
        state.tokens.push(token);
        if (list[i].tokens) {
          tokens = [];
          token = new state.Token("paragraph_open", "p", 1);
          token.block = true;
          tokens.push(token);
          token = new state.Token("inline", "", 0);
          token.children = list[i].tokens;
          token.content = list[i].content;
          tokens.push(token);
          token = new state.Token("paragraph_close", "p", -1);
          token.block = true;
          tokens.push(token);
        } else if (list[i].label) {
          tokens = refTokens[":" + list[i].label];
        }
        state.tokens = state.tokens.concat(tokens);
        if (state.tokens[state.tokens.length - 1].type === "paragraph_close") {
          lastParagraph = state.tokens.pop();
        } else {
          lastParagraph = null;
        }
        t = list[i].count > 0 ? list[i].count : 1;
        for (j = 0; j < t; j++) {
          token = new state.Token("footnote_anchor", "", 0);
          token.meta = {
            id: i,
            subId: j,
            label: list[i].label
          };
          state.tokens.push(token);
        }
        if (lastParagraph) {
          state.tokens.push(lastParagraph);
        }
        token = new state.Token("footnote_close", "", -1);
        state.tokens.push(token);
      }
      token = new state.Token("footnote_block_close", "", -1);
      state.tokens.push(token);
    }
    md.block.ruler.before("reference", "footnote_def", footnote_def, {
      alt: [ "paragraph", "reference" ]
    });
    md.inline.ruler.after("image", "footnote_inline", footnote_inline);
    md.inline.ruler.after("footnote_inline", "footnote_ref", footnote_ref);
    md.core.ruler.after("inline", "footnote_tail", footnote_tail);
  };
  var markdownItIns = function ins_plugin(md) {
    // Insert each marker as a separate text token, and add it to delimiter list
    function tokenize(state, silent) {
      var i, scanned, token, len, ch, start = state.pos, marker = state.src.charCodeAt(start);
      if (silent) {
        return false;
      }
      if (marker !== 43 /* + */) {
        return false;
      }
      scanned = state.scanDelims(state.pos, true);
      len = scanned.length;
      ch = String.fromCharCode(marker);
      if (len < 2) {
        return false;
      }
      if (len % 2) {
        token = state.push("text", "", 0);
        token.content = ch;
        len--;
      }
      for (i = 0; i < len; i += 2) {
        token = state.push("text", "", 0);
        token.content = ch + ch;
        if (!scanned.can_open && !scanned.can_close) {
          continue;
        }
        state.delimiters.push({
          marker: marker,
          length: 0,
          // disable "rule of 3" length checks meant for emphasis
          jump: i,
          token: state.tokens.length - 1,
          end: -1,
          open: scanned.can_open,
          close: scanned.can_close
        });
      }
      state.pos += scanned.length;
      return true;
    }
    // Walk through delimiter list and replace text tokens with tags
    
        function postProcess(state, delimiters) {
      var i, j, startDelim, endDelim, token, loneMarkers = [], max = delimiters.length;
      for (i = 0; i < max; i++) {
        startDelim = delimiters[i];
        if (startDelim.marker !== 43 /* + */) {
          continue;
        }
        if (startDelim.end === -1) {
          continue;
        }
        endDelim = delimiters[startDelim.end];
        token = state.tokens[startDelim.token];
        token.type = "ins_open";
        token.tag = "ins";
        token.nesting = 1;
        token.markup = "++";
        token.content = "";
        token = state.tokens[endDelim.token];
        token.type = "ins_close";
        token.tag = "ins";
        token.nesting = -1;
        token.markup = "++";
        token.content = "";
        if (state.tokens[endDelim.token - 1].type === "text" && state.tokens[endDelim.token - 1].content === "+") {
          loneMarkers.push(endDelim.token - 1);
        }
      }
      // If a marker sequence has an odd number of characters, it's splitted
      // like this: `~~~~~` -> `~` + `~~` + `~~`, leaving one marker at the
      // start of the sequence.
      
      // So, we have to move all those markers after subsequent s_close tags.
      
            while (loneMarkers.length) {
        i = loneMarkers.pop();
        j = i + 1;
        while (j < state.tokens.length && state.tokens[j].type === "ins_close") {
          j++;
        }
        j--;
        if (i !== j) {
          token = state.tokens[j];
          state.tokens[j] = state.tokens[i];
          state.tokens[i] = token;
        }
      }
    }
    md.inline.ruler.before("emphasis", "ins", tokenize);
    md.inline.ruler2.before("emphasis", "ins", (function(state) {
      var curr, tokens_meta = state.tokens_meta, max = (state.tokens_meta || []).length;
      postProcess(state, state.delimiters);
      for (curr = 0; curr < max; curr++) {
        if (tokens_meta[curr] && tokens_meta[curr].delimiters) {
          postProcess(state, tokens_meta[curr].delimiters);
        }
      }
    }));
  };
  var markdownItMark = function ins_plugin(md) {
    // Insert each marker as a separate text token, and add it to delimiter list
    function tokenize(state, silent) {
      var i, scanned, token, len, ch, start = state.pos, marker = state.src.charCodeAt(start);
      if (silent) {
        return false;
      }
      if (marker !== 61 /* = */) {
        return false;
      }
      scanned = state.scanDelims(state.pos, true);
      len = scanned.length;
      ch = String.fromCharCode(marker);
      if (len < 2) {
        return false;
      }
      if (len % 2) {
        token = state.push("text", "", 0);
        token.content = ch;
        len--;
      }
      for (i = 0; i < len; i += 2) {
        token = state.push("text", "", 0);
        token.content = ch + ch;
        if (!scanned.can_open && !scanned.can_close) {
          continue;
        }
        state.delimiters.push({
          marker: marker,
          length: 0,
          // disable "rule of 3" length checks meant for emphasis
          jump: i,
          token: state.tokens.length - 1,
          end: -1,
          open: scanned.can_open,
          close: scanned.can_close
        });
      }
      state.pos += scanned.length;
      return true;
    }
    // Walk through delimiter list and replace text tokens with tags
    
        function postProcess(state, delimiters) {
      var i, j, startDelim, endDelim, token, loneMarkers = [], max = delimiters.length;
      for (i = 0; i < max; i++) {
        startDelim = delimiters[i];
        if (startDelim.marker !== 61 /* = */) {
          continue;
        }
        if (startDelim.end === -1) {
          continue;
        }
        endDelim = delimiters[startDelim.end];
        token = state.tokens[startDelim.token];
        token.type = "mark_open";
        token.tag = "mark";
        token.nesting = 1;
        token.markup = "==";
        token.content = "";
        token = state.tokens[endDelim.token];
        token.type = "mark_close";
        token.tag = "mark";
        token.nesting = -1;
        token.markup = "==";
        token.content = "";
        if (state.tokens[endDelim.token - 1].type === "text" && state.tokens[endDelim.token - 1].content === "=") {
          loneMarkers.push(endDelim.token - 1);
        }
      }
      // If a marker sequence has an odd number of characters, it's splitted
      // like this: `~~~~~` -> `~` + `~~` + `~~`, leaving one marker at the
      // start of the sequence.
      
      // So, we have to move all those markers after subsequent s_close tags.
      
            while (loneMarkers.length) {
        i = loneMarkers.pop();
        j = i + 1;
        while (j < state.tokens.length && state.tokens[j].type === "mark_close") {
          j++;
        }
        j--;
        if (i !== j) {
          token = state.tokens[j];
          state.tokens[j] = state.tokens[i];
          state.tokens[i] = token;
        }
      }
    }
    md.inline.ruler.before("emphasis", "mark", tokenize);
    md.inline.ruler2.before("emphasis", "mark", (function(state) {
      var curr, tokens_meta = state.tokens_meta, max = (state.tokens_meta || []).length;
      postProcess(state, state.delimiters);
      for (curr = 0; curr < max; curr++) {
        if (tokens_meta[curr] && tokens_meta[curr].delimiters) {
          postProcess(state, tokens_meta[curr].delimiters);
        }
      }
    }));
  };
  // Process ~subscript~
  // same as UNESCAPE_MD_RE plus a space
    var UNESCAPE_RE = /\\([ \\!"#$%&'()*+,.\/:;<=>?@[\]^_`{|}~-])/g;
  function subscript(state, silent) {
    var found, content, token, max = state.posMax, start = state.pos;
    if (state.src.charCodeAt(start) !== 126 /* ~ */) {
      return false;
    }
    if (silent) {
      return false;
    }
 // don't run any pairs in validation mode
        if (start + 2 >= max) {
      return false;
    }
    state.pos = start + 1;
    while (state.pos < max) {
      if (state.src.charCodeAt(state.pos) === 126 /* ~ */) {
        found = true;
        break;
      }
      state.md.inline.skipToken(state);
    }
    if (!found || start + 1 === state.pos) {
      state.pos = start;
      return false;
    }
    content = state.src.slice(start + 1, state.pos);
    // don't allow unescaped spaces/newlines inside
        if (content.match(/(^|[^\\])(\\\\)*\s/)) {
      state.pos = start;
      return false;
    }
    // found!
        state.posMax = state.pos;
    state.pos = start + 1;
    // Earlier we checked !silent, but this implementation does not need it
        token = state.push("sub_open", "sub", 1);
    token.markup = "~";
    token = state.push("text", "", 0);
    token.content = content.replace(UNESCAPE_RE, "$1");
    token = state.push("sub_close", "sub", -1);
    token.markup = "~";
    state.pos = state.posMax + 1;
    state.posMax = max;
    return true;
  }
  var markdownItSub = function sub_plugin(md) {
    md.inline.ruler.after("emphasis", "sub", subscript);
  };
  // Process ^superscript^
  // same as UNESCAPE_MD_RE plus a space
    var UNESCAPE_RE$1 = /\\([ \\!"#$%&'()*+,.\/:;<=>?@[\]^_`{|}~-])/g;
  function superscript(state, silent) {
    var found, content, token, max = state.posMax, start = state.pos;
    if (state.src.charCodeAt(start) !== 94 /* ^ */) {
      return false;
    }
    if (silent) {
      return false;
    }
 // don't run any pairs in validation mode
        if (start + 2 >= max) {
      return false;
    }
    state.pos = start + 1;
    while (state.pos < max) {
      if (state.src.charCodeAt(state.pos) === 94 /* ^ */) {
        found = true;
        break;
      }
      state.md.inline.skipToken(state);
    }
    if (!found || start + 1 === state.pos) {
      state.pos = start;
      return false;
    }
    content = state.src.slice(start + 1, state.pos);
    // don't allow unescaped spaces/newlines inside
        if (content.match(/(^|[^\\])(\\\\)*\s/)) {
      state.pos = start;
      return false;
    }
    // found!
        state.posMax = state.pos;
    state.pos = start + 1;
    // Earlier we checked !silent, but this implementation does not need it
        token = state.push("sup_open", "sup", 1);
    token.markup = "^";
    token = state.push("text", "", 0);
    token.content = content.replace(UNESCAPE_RE$1, "$1");
    token = state.push("sup_close", "sup", -1);
    token.markup = "^";
    state.pos = state.posMax + 1;
    state.posMax = max;
    return true;
  }
  var markdownItSup = function sup_plugin(md) {
    md.inline.ruler.after("emphasis", "sup", superscript);
  };
  /*eslint-env browser*/
  /*global $, _*/  core.registerLanguage("actionscript", actionscript_1);
  core.registerLanguage("apache", apache_1);
  core.registerLanguage("armasm", armasm_1);
  core.registerLanguage("xml", xml_1);
  core.registerLanguage("asciidoc", asciidoc_1);
  core.registerLanguage("avrasm", avrasm_1);
  core.registerLanguage("bash", bash_1);
  core.registerLanguage("clojure", clojure_1);
  core.registerLanguage("cmake", cmake_1);
  core.registerLanguage("coffeescript", coffeescript_1);
  core.registerLanguage("c-like", cLike_1);
  core.registerLanguage("c", c_1);
  core.registerLanguage("cpp", cpp_1);
  core.registerLanguage("arduino", arduino_1);
  core.registerLanguage("css", css_1);
  core.registerLanguage("diff", diff_1);
  core.registerLanguage("django", django_1);
  core.registerLanguage("dockerfile", dockerfile_1);
  core.registerLanguage("ruby", ruby_1);
  core.registerLanguage("fortran", fortran_1);
  core.registerLanguage("glsl", glsl_1);
  core.registerLanguage("go", go_1);
  core.registerLanguage("groovy", groovy_1);
  core.registerLanguage("handlebars", handlebars_1);
  core.registerLanguage("haskell", haskell_1);
  core.registerLanguage("ini", ini_1);
  core.registerLanguage("java", java_1);
  core.registerLanguage("javascript", javascript_1);
  core.registerLanguage("json", json_1);
  core.registerLanguage("latex", latex_1);
  core.registerLanguage("less", less_1);
  core.registerLanguage("lisp", lisp_1);
  core.registerLanguage("livescript", livescript_1);
  core.registerLanguage("lua", lua_1);
  core.registerLanguage("makefile", makefile_1);
  core.registerLanguage("matlab", matlab_1);
  core.registerLanguage("mipsasm", mipsasm_1);
  core.registerLanguage("perl", perl_1);
  core.registerLanguage("nginx", nginx_1);
  core.registerLanguage("objectivec", objectivec_1);
  core.registerLanguage("php", php_1);
  core.registerLanguage("python", python_1);
  core.registerLanguage("rust", rust_1);
  core.registerLanguage("scala", scala_1);
  core.registerLanguage("scheme", scheme_1);
  core.registerLanguage("scss", scss_1);
  core.registerLanguage("smalltalk", smalltalk_1);
  core.registerLanguage("stylus", stylus_1);
  core.registerLanguage("swift", swift_1);
  core.registerLanguage("tcl", tcl_1);
  core.registerLanguage("typescript", typescript_1);
  core.registerLanguage("verilog", verilog_1);
  core.registerLanguage("vhdl", vhdl_1);
  core.registerLanguage("yaml", yaml_1);
  var mdHtml, mdSrc, permalink, scrollMap;
  var defaults = {
    html: false,
    // Enable HTML tags in source
    xhtmlOut: false,
    // Use '/' to close single tags (<br />)
    breaks: false,
    // Convert '\n' in paragraphs into <br>
    langPrefix: "language-",
    // CSS language prefix for fenced blocks
    linkify: true,
    // autoconvert URL-like texts to links
    typographer: true,
    // Enable smartypants and other sweet transforms
    // options below are for demo only
    _highlight: true,
    _strict: false,
    _view: "html"
  };
  defaults.highlight = function(str, lang) {
    var esc = mdHtml.utils.escapeHtml;
    try {
      if (!defaults._highlight) {
        throw "highlighting disabled";
      }
      if (lang && lang !== "auto" && core.getLanguage(lang)) {
        return '<pre class="hljs language-' + esc(lang.toLowerCase()) + '"><code>' + core.highlight(lang, str, true).value + "</code></pre>";
      } else if (lang === "auto") {
        var result = core.highlightAuto(str);
        /*eslint-disable no-console*/        console.log("highlight language: " + result.language + ", relevance: " + result.relevance);
        return '<pre class="hljs language-' + esc(result.language) + '"><code>' + result.value + "</code></pre>";
      }
    } catch (__) {}
    return '<pre class="hljs"><code>' + esc(str) + "</code></pre>";
  };
  function setOptionClass(name, val) {
    if (val) {
      $("body").addClass("opt_" + name);
    } else {
      $("body").removeClass("opt_" + name);
    }
  }
  function setResultView(val) {
    $("body").removeClass("result-as-html");
    $("body").removeClass("result-as-src");
    $("body").removeClass("result-as-debug");
    $("body").addClass("result-as-" + val);
    defaults._view = val;
  }
  function mdInit() {
    if (defaults._strict) {
      mdHtml = window.markdownit("commonmark");
      mdSrc = window.markdownit("commonmark");
    } else {
      mdHtml = window.markdownit(defaults).use(markdownItAbbr).use(markdownItContainer, "warning").use(markdownItDeflist).use(markdownItEmoji).use(markdownItFootnote).use(markdownItIns).use(markdownItMark).use(markdownItSub).use(markdownItSup);
      mdSrc = window.markdownit(defaults).use(markdownItAbbr).use(markdownItContainer, "warning").use(markdownItDeflist).use(markdownItEmoji).use(markdownItFootnote).use(markdownItIns).use(markdownItMark).use(markdownItSub).use(markdownItSup);
    }
    // Beautify output of parser for html content
        mdHtml.renderer.rules.table_open = function() {
      return '<table class="table table-striped">\n';
    };
    // Replace emoji codes with images
        mdHtml.renderer.rules.emoji = function(token, idx) {
      return window.twemoji.parse(token[idx].content);
    };
    
    // Inject line numbers for sync scroll. Notes:
    
    // - We track only headings and paragraphs on first level. That's enough.
    // - Footnotes content causes jumps. Level limit filter it automatically.
        function injectLineNumbers(tokens, idx, options, env, slf) {
      var line;
      if (tokens[idx].map && tokens[idx].level === 0) {
        line = tokens[idx].map[0];
        tokens[idx].attrJoin("class", "line");
        tokens[idx].attrSet("data-line", String(line));
      }
      return slf.renderToken(tokens, idx, options, env, slf);
    }
    mdHtml.renderer.rules.paragraph_open = mdHtml.renderer.rules.heading_open = injectLineNumbers;
  }
  function setHighlightedlContent(selector, content, lang) {
    if (window.hljs) {
      $(selector).html(window.hljs.highlight(lang, content).value);
    } else {
      $(selector).text(content);
    }
  }
  function updateResult() {
    var source = $(".source").val();
    // Update only active view to avoid slowdowns
    // (debug & src view with highlighting are a bit slow)
        if (defaults._view === "src") {
      setHighlightedlContent(".result-src-content", mdSrc.render(source), "html");
    } else if (defaults._view === "debug") {
      setHighlightedlContent(".result-debug-content", JSON.stringify(mdSrc.parse(source, {
        references: {}
      }), null, 2), "json");
    } else {
      /*defaults._view === 'html'*/
      $(".result-html").html(mdHtml.render(source));
    }
    // reset lines mapping cache on content update
        scrollMap = null;
    try {
      if (source) {
        // serialize state - source and options
        permalink.href = "#md3=" + mdurl.encode(JSON.stringify({
          source: source,
          defaults: _.omit(defaults, "highlight")
        }), "-_.!~", false);
      } else {
        permalink.href = "";
      }
    } catch (__) {
      permalink.href = "";
    }
  }
  // Build offsets for each line (lines can be wrapped)
  // That's a bit dirty to process each line everytime, but ok for demo.
  // Optimizations are required only for big texts.
    function buildScrollMap() {
    var i, offset, nonEmptyList, pos, a, b, lineHeightMap, linesCount, acc, sourceLikeDiv, textarea = $(".source"), _scrollMap;
    sourceLikeDiv = $("<div />").css({
      position: "absolute",
      visibility: "hidden",
      height: "auto",
      width: textarea[0].clientWidth,
      "font-size": textarea.css("font-size"),
      "font-family": textarea.css("font-family"),
      "line-height": textarea.css("line-height"),
      "white-space": textarea.css("white-space")
    }).appendTo("body");
    offset = $(".result-html").scrollTop() - $(".result-html").offset().top;
    _scrollMap = [];
    nonEmptyList = [];
    lineHeightMap = [];
    acc = 0;
    textarea.val().split("\n").forEach((function(str) {
      var h, lh;
      lineHeightMap.push(acc);
      if (str.length === 0) {
        acc++;
        return;
      }
      sourceLikeDiv.text(str);
      h = parseFloat(sourceLikeDiv.css("height"));
      lh = parseFloat(sourceLikeDiv.css("line-height"));
      acc += Math.round(h / lh);
    }));
    sourceLikeDiv.remove();
    lineHeightMap.push(acc);
    linesCount = acc;
    for (i = 0; i < linesCount; i++) {
      _scrollMap.push(-1);
    }
    nonEmptyList.push(0);
    _scrollMap[0] = 0;
    $(".line").each((function(n, el) {
      var $el = $(el), t = $el.data("line");
      if (t === "") {
        return;
      }
      t = lineHeightMap[t];
      if (t !== 0) {
        nonEmptyList.push(t);
      }
      _scrollMap[t] = Math.round($el.offset().top + offset);
    }));
    nonEmptyList.push(linesCount);
    _scrollMap[linesCount] = $(".result-html")[0].scrollHeight;
    pos = 0;
    for (i = 1; i < linesCount; i++) {
      if (_scrollMap[i] !== -1) {
        pos++;
        continue;
      }
      a = nonEmptyList[pos];
      b = nonEmptyList[pos + 1];
      _scrollMap[i] = Math.round((_scrollMap[b] * (i - a) + _scrollMap[a] * (b - i)) / (b - a));
    }
    return _scrollMap;
  }
  // Synchronize scroll position from source to result
    var syncResultScroll = _.debounce((function() {
    var textarea = $(".source"), lineHeight = parseFloat(textarea.css("line-height")), lineNo, posTo;
    lineNo = Math.floor(textarea.scrollTop() / lineHeight);
    if (!scrollMap) {
      scrollMap = buildScrollMap();
    }
    posTo = scrollMap[lineNo];
    $(".result-html").stop(true).animate({
      scrollTop: posTo
    }, 100, "linear");
  }), 50, {
    maxWait: 50
  });
  // Synchronize scroll position from result to source
    var syncSrcScroll = _.debounce((function() {
    var resultHtml = $(".result-html"), scrollTop = resultHtml.scrollTop(), textarea = $(".source"), lineHeight = parseFloat(textarea.css("line-height")), lines, i, line;
    if (!scrollMap) {
      scrollMap = buildScrollMap();
    }
    lines = Object.keys(scrollMap);
    if (lines.length < 1) {
      return;
    }
    line = lines[0];
    for (i = 1; i < lines.length; i++) {
      if (scrollMap[lines[i]] < scrollTop) {
        line = lines[i];
        continue;
      }
      break;
    }
    textarea.stop(true).animate({
      scrollTop: lineHeight * line
    }, 100, "linear");
  }), 50, {
    maxWait: 50
  });
  function loadPermalink() {
    if (!location.hash) {
      return;
    }
    var cfg, opts;
    try {
      if (/^#md3=/.test(location.hash)) {
        cfg = JSON.parse(mdurl.decode(location.hash.slice(5), mdurl.decode.componentChars));
      } else if (/^#md64=/.test(location.hash)) {
        cfg = JSON.parse(window.atob(location.hash.slice(6)));
      } else if (/^#md=/.test(location.hash)) {
        cfg = JSON.parse(decodeURIComponent(location.hash.slice(4)));
      } else {
        return;
      }
      if (_.isString(cfg.source)) {
        $(".source").val(cfg.source);
      }
    } catch (__) {
      return;
    }
    opts = _.isObject(cfg.defaults) ? cfg.defaults : {};
    // copy config to defaults, but only if key exists
    // and value has the same type
        _.forOwn(opts, (function(val, key) {
      if (!_.has(defaults, key)) {
        return;
      }
      // Legacy, for old links
            if (key === "_src") {
        defaults._view = val ? "src" : "html";
        return;
      }
      if (_.isBoolean(defaults[key]) && _.isBoolean(val) || _.isString(defaults[key]) && _.isString(val)) {
        defaults[key] = val;
      }
    }));
    // sanitize for sure
        if ([ "html", "src", "debug" ].indexOf(defaults._view) === -1) {
      defaults._view = "html";
    }
  }
  //////////////////////////////////////////////////////////////////////////////
  // Init on page load
  
    $((function() {
    // highlight snippet
    if (window.hljs) {
      $("pre.code-sample code").each((function(i, block) {
        window.hljs.highlightBlock(block);
      }));
    }
    loadPermalink();
    // Activate tooltips
        $("._tip").tooltip({
      container: "body"
    });
    // Set default option values and option listeners
        _.forOwn(defaults, (function(val, key) {
      if (key === "highlight") {
        return;
      }
      var el = document.getElementById(key);
      if (!el) {
        return;
      }
      var $el = $(el);
      if (_.isBoolean(val)) {
        $el.prop("checked", val);
        $el.on("change", (function() {
          var value = Boolean($el.prop("checked"));
          setOptionClass(key, value);
          defaults[key] = value;
          mdInit();
          updateResult();
        }));
        setOptionClass(key, val);
      } else {
        $(el).val(val);
        $el.on("change update keyup", (function() {
          defaults[key] = String($(el).val());
          mdInit();
          updateResult();
        }));
      }
    }));
    setResultView(defaults._view);
    mdInit();
    permalink = document.getElementById("permalink");
    // Setup listeners
        $(".source").on("keyup paste cut mouseup", _.debounce(updateResult, 300, {
      maxWait: 500
    }));
    $(".source").on("touchstart mouseover", (function() {
      $(".result-html").off("scroll");
      $(".source").on("scroll", syncResultScroll);
    }));
    $(".result-html").on("touchstart mouseover", (function() {
      $(".source").off("scroll");
      $(".result-html").on("scroll", syncSrcScroll);
    }));
    $(".source-clear").on("click", (function(event) {
      $(".source").val("");
      updateResult();
      event.preventDefault();
    }));
    $(document).on("click", "[data-result-as]", (function(event) {
      var view = $(this).data("resultAs");
      if (view) {
        setResultView(view);
        // only to update permalink
                updateResult();
        event.preventDefault();
      }
    }));
    // Need to recalculate line positions on window resize
        $(window).on("resize", (function() {
      scrollMap = null;
    }));
    updateResult();
  }));
  var demo_template = {};
  return demo_template;
}();
