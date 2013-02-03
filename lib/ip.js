var ip = exports,
    Buffer = require('buffer').Buffer,
    os = require('os');

ip.toBuffer = function toBuffer(ip) {
  var result;

  if (/^(\d{1,3}\.){3,3}\d{1,3}$/.test(ip)) {
    result = new Buffer(ip.split(/\./g).map(function(byte) {
      return parseInt(byte, 10) & 0xff;
    }));
  } else if (/^[a-f0-9:]+$/.test(ip)) {
    var s = ip.split(/::/g, 2),
        head = (s[0] || '').split(/:/g, 8),
        tail = (s[1] || '').split(/:/g, 8);

    if (tail.length === 0) {
      // xxxx::
      while (head.length < 8) head.push('0000');
    } else if (head.length === 0) {
      // ::xxxx
      while (tail.length < 8) tail.unshift('0000');
    } else {
      // xxxx::xxxx
      while (head.length + tail.length < 8) head.push('0000');
    }

    result = new Buffer(head.concat(tail).map(function(word) {
      word = parseInt(word, 16);
      return [(word >> 8) & 0xff, word & 0xff];
    }).reduce(function(prev, next) {
      return prev.concat(next);
    }));
  } else {
    throw Error('Invalid ip address: ' + ip);
  }

  return result;
};

ip.toString = function toString(buff) {
  var result = [];
  if (buff.length === 4) {
    // IPv4
    for (var i = 0; i < buff.length; i++) {
      result.push(buff[i]);
    }
    result = result.join('.');
  } else if (buff.length === 16) {
    // IPv6
    for (var i = 0; i < buff.length; i += 2) {
      result.push(buff.readUInt16BE(i).toString(16));
    }
    result = result.join(':');
    result = result.replace(/(^|:)0(:0)*:0(:|$)/, '$1::$3');
    result = result.replace(/:{3,4}/, '::');
  }

  return result;
};

ip.mask = function mask(addr, mask) {
  addr = ip.toBuffer(addr);
  mask = ip.toBuffer(mask);

  var result = new Buffer(Math.max(addr.length, mask.length));

  // Same protocol - do bitwise and
  if (addr.length === mask.length) {
    for (var i = 0; i < addr.length; i++) {
      result[i] = addr[i] & mask[i];
    }
  } else if (mask.length === 4) {
    // IPv6 address and IPv4 mask
    // (Mask low bits)
    for (var i = 0; i < mask.length; i++) {
      result[i] = addr[addr.length - 4  + i] & mask[i];
    }
  } else {
    // IPv6 mask and IPv4 addr
    for (var i = 0; i < result.length - 6; i++) {
      result[i] = 0;
    }

    // ::ffff:ipv4
    result[10] = 0xff;
    result[11] = 0xff;
    for (var i = 0; i < addr.length; i++) {
      result[i + 12] = addr[i] & mask[i + 12];
    }
  }

  return ip.toString(result);
};

ip.not = function not(addr) {
  var buff = ip.toBuffer(addr);
  for (var i = 0; i < buff.length; i++) {
    buff[i] = 0xff ^ buff[i];
  }
  return ip.toString(buff);
};

ip.isEqual = function isEqual(a, b) {
  a = ip.toBuffer(a);
  b = ip.toBuffer(b);

  // Same protocol
  if (a.length === b.length) {
    for (var i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  // Swap
  if (b.length === 4) {
    var t = b;
    b = a;
    a = t;
  }

  // a - IPv4, b - IPv6
  for (var i = 0; i < 10; i++) {
    if (b[i] !== 0) return false;
  }

  var word = b.readUInt16BE(10);
  if (word !== 0 && word !== 0xffff) return false;

  for (var i = 0; i < 4; i++) {
    if (a[i] !== b[i + 12]) return false;
  }

  return true;
};

ip.isPrivate = function isPrivate(addr) {
  return addr.match(/^10\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/) != null ||
    addr.match(/^192\.168\.([0-9]{1,3})\.([0-9]{1,3})/) != null ||
    addr.match(/^172\.16\.([0-9]{1,3})\.([0-9]{1,3})/) != null ||
    addr.match(/^127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/) != null ||
    addr.match(/^169\.254\.([0-9]{1,3})\.([0-9]{1,3})/) != null ||
    addr.match(/^fc00:/) != null || addr.match(/^fe80:/) != null;
};

ip.isPublic = function isPublic(addr) {
  return !ip.isPrivate(addr);
}

ip.isLoopback = function isLoopback(addr) {
  return /^127\.0\.0\.1/.test(addr)
    || /^fe80::1/.test(addr)
    || /^::1/.test(addr);
};

ip.loopback = function loopback(family) {
  //
  // Default to `ipv4`
  //
  family = family
    ? family.toLowerCase()
    : 'ipv4';

  if (family !== 'ipv4' && family !== 'ipv6') {
    throw new Error('family must be ipv4 or ipv6');
  }

  return family === 'ipv4'
    ? '127.0.0.1'
    : 'fe80::1';
};

//
// ### function address (name, family)
// #### @name {string|'public'|'private'} **Optional** Name or security
//      of the network interface.
// #### @family {ipv4|ipv6} **Optional** IP family of the address (defaults
//      to ipv4).
//
// Returns the address for the network interface on the current system with
// the specified `name`:
//   * String: First `family` address of the interface. If not found see `undefined`.
//   * 'public': the first public ip address of family.
//   * 'private': the first private ip address of family.
//   * undefined: First address with `ipv4` or loopback addres `127.0.0.1`.
//
ip.address = function address(name, family) {
  var interfaces = os.networkInterfaces(),
      all;

  //
  // Default to `ipv4`
  //
  family = family
    ? family.toLowerCase()
    : 'ipv4';

  //
  // If a specific network interface has been named,
  // return the address.
  //
  if (name && !~['public', 'private'].indexOf(name)) {
    return interfaces[name].filter(function (details) {
      details.family = details.family.toLowerCase();
      return details.family === family;
    })[0].address;
  }

  var all = Object.keys(interfaces).map(function (nic) {
    //
    // Note: name will only be `public` or `private`
    // when this is called.
    //
    var addresses = interfaces[nic].filter(function (details) {
      details.family = details.family.toLowerCase();
      if (details.family !== family || ip.isLoopback(details.address)) {
        return false;
      }
      else if (!name) {
        return true;
      }

      return name === 'public'
        ? !ip.isPrivate(details.address)
        : ip.isPrivate(details.address)
    });

    return addresses.length
      ? addresses[0].address
      : undefined;
  }).filter(Boolean);

  return !all.length
    ? ip.loopback(family)
    : all[0];
};
