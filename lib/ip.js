import { networkInterfaces } from 'node:os';

/** @typedef {ReturnType<typeof subnet>} SubnetInfo */

const ipv4Regex = /^(\d{1,3}\.){3,3}\d{1,3}$/;
const ipv6Regex = /^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i;

/**
 * Encode a Uint8Array to a hex string
 *
 * @param {Uint8Array} array Bytes to encode to string
 */
const arr2hex = array => {
  let result = '';
  for (const value of array) {
    result += value.toString(16).padStart(2, '0');
  }
  return result;
};

/**
 * Convert an IP string into a Uint8array.
 *
 * @param {string} ip
 * @param {Uint8Array} [buff]
 * @param {number} [offset=0]
 */
function toBuffer(ip, buff, offset = 0) {
  let result;

  if (isV4Format(ip)) {
    result = buff || new Uint8Array(offset + 4);
    ip.split(/\./g).map((byte) => {
      result[offset++] = parseInt(byte, 10) & 0xff;
    });
  } else if (isV6Format(ip)) {
    const sections = ip.split(':', 8);

    let i;
    for (i = 0; i < sections.length; i++) {
      const isv4 = isV4Format(sections[i]);
      let v4Buffer;

      if (isv4) {
        v4Buffer = toBuffer(sections[i]);
        sections[i] = arr2hex(v4Buffer.subarray(0, 2));
      }

      if (v4Buffer && ++i < 8) {
        sections.splice(i, 0, arr2hex(v4Buffer.subarray(2, 4)));
      }
    }

    if (sections[0] === '') {
      while (sections.length < 8) sections.unshift('0');
    } else if (sections[sections.length - 1] === '') {
      while (sections.length < 8) sections.push('0');
    } else if (sections.length < 8) {
      for (i = 0; i < sections.length && sections[i] !== ''; i++);
      const argv = [i, 1];
      for (i = 9 - sections.length; i > 0; i--) {
        argv.push('0');
      }
      sections.splice(...argv);
    }

    result = buff || new Uint8Array(offset + 16);
    for (i = 0; i < sections.length; i++) {
      const word = parseInt(sections[i], 16);
      result[offset++] = (word >> 8) & 0xff;
      result[offset++] = word & 0xff;
    }
  }

  if (!result) {
    throw Error(`Invalid ip address: ${ip}`);
  }

  return result;
}

/**
 * Convert an IP buffer into a string.
 *
 * @param {Uint8Array} buff
 */
function toString(buff, offset = 0, length = buff.length - offset) {
  let result = [];

  if (length === 4) {
    // IPv4
    for (let i = 0; i < length; i++) {
      result.push(buff[offset + i]);
    }
    return result.join('.');
  } else if (length === 16) {
    // IPv6
    for (let i = 0; i < length; i += 2) {
      result.push(buff.readUInt16BE(offset + i).toString(16));
    }
    return result.join(':')
      .replace(/(^|:)0(:0)*:0(:|$)/, '$1::$3')
      .replace(/:{3,4}/, '::');
  }

  return '';
}

/**
 * Check whether an IP is a IPv4 address
 *
 * @param {string} ip
 */
function isV4Format(ip) {
  return ipv4Regex.test(ip);
}

/**
 * Check whether an IP is a IPv6 address
 *
 * @param {string} ip
 */
function isV6Format(ip) {
  return ipv6Regex.test(ip);
}

/**
 * @description Normalize the given family.
 * @param {string | number} family
 * @returns {string}
 */
function _normalizeFamily(family) {
  return family === 4 ? 'ipv4' :
    family === 6 ? 'ipv6' :
      family ? family.toLowerCase() : 'ipv4';
}

/**
 * Get the subnet mask from a CIDR prefix length.
 *
 * @param {number} prefixlen
 * @param {'ipv4' | 'ipv6'} [family]
 * The IP family is inferred from the prefixLength, but can be explicity
 * specified as either "ipv4" or "ipv6".
 */
function fromPrefixLen(prefixlen, family) {
  family = prefixlen > 32 ? 'ipv6' : _normalizeFamily(family);

  const len = family === 'ipv6' ? 16 : 4;
  const buff = new Uint8Array(len);

  for (let i = 0, n = buff.length; i < n; ++i) {
    let bits = 8;
    if (prefixlen < 8) {
      bits = prefixlen;
    }
    prefixlen -= bits;

    buff[i] = ~(0xff >> bits) & 0xff;
  }

  return toString(buff);
}

/**
 * Get the network ID IP address from an IP address and its subnet mask.
 *
 * @param {string} ipAddr
 * @param {string} ipMask
 */
function _mask(ipAddr, ipMask) {
  const addr = toBuffer(ipAddr);
  const mask = toBuffer(ipMask);

  const result = new Uint8Array(Math.max(addr.length, mask.length));

  // Same protocol - do bitwise and
  let i;
  if (addr.length === mask.length) {
    for (i = 0; i < addr.length; i++) {
      result[i] = addr[i] & mask[i];
    }
  } else if (mask.length === 4) {
    // IPv6 address and IPv4 mask
    // (Mask low bits)
    for (i = 0; i < mask.length; i++) {
      result[i] = addr[addr.length - 4 + i] & mask[i];
    }
  } else {
    // IPv6 mask and IPv4 addr
    for (i = 0; i < result.length - 6; i++) {
      result[i] = 0;
    }

    // ::ffff:ipv4
    result[10] = 0xff;
    result[11] = 0xff;
    for (i = 0; i < addr.length; i++) {
      result[i + 12] = addr[i] & mask[i + 12];
    }
    i += 12;
  }
  for (; i < result.length; i++) {
    result[i] = 0;
  }

  return toString(result);
}

/**
 * Get the network ID IP address from an IP address in CIDR notation.
 *
 * @param {string} cidrString
 */
function cidr(cidrString) {
  const cidrParts = cidrString.split('/');

  const addr = cidrParts[0];
  if (cidrParts.length !== 2) {
    throw new Error(`invalid CIDR subnet: ${addr}`);
  }

  const mask = fromPrefixLen(parseInt(cidrParts[1], 10));

  return _mask(addr, mask);
}

/**
 * Get the subnet information.
 *
 * @param {string} ip IP address.
 * @param {string} subnet Subnet address.
 */
function subnet(ip, subnet) {
  const networkAddress = toLong(_mask(ip, subnet));

  // Calculate the mask's length.
  const maskBuffer = toBuffer(subnet);
  let maskLength = 0;

  for (let i = 0; i < maskBuffer.length; i++) {
    if (maskBuffer[i] === 0xff) {
      maskLength += 8;
    } else {
      let octet = maskBuffer[i] & 0xff;
      while (octet) {
        octet = (octet << 1) & 0xff;
        maskLength++;
      }
    }
  }

  const numberOfAddresses = 2 ** (32 - maskLength);

  return {
    networkAddress: fromLong(networkAddress),
    firstAddress: numberOfAddresses <= 2
      ? fromLong(networkAddress)
      : fromLong(networkAddress + 1),
    lastAddress: numberOfAddresses <= 2
      ? fromLong(networkAddress + numberOfAddresses - 1)
      : fromLong(networkAddress + numberOfAddresses - 2),
    broadcastAddress: fromLong(networkAddress + numberOfAddresses - 1),
    subnetMask: subnet,
    subnetMaskLength: maskLength,
    numHosts: numberOfAddresses <= 2
      ? numberOfAddresses : numberOfAddresses - 2,
    length: numberOfAddresses,
    contains(other) {
      return networkAddress === toLong(_mask(other, subnet));
    },
  };
}

/**
 * Get the subnet information.
 * @param {string} cidrString CIDR address.
 */
function cidrSubnet(cidrString) {
  const cidrParts = cidrString.split('/');

  const addr = cidrParts[0];
  if (cidrParts.length !== 2) {
    throw new Error(`invalid CIDR subnet: ${addr}`);
  }

  const mask = fromPrefixLen(parseInt(cidrParts[1], 10));

  return subnet(addr, mask);
}

/**
 * Get the bitwise inverse (NOT every octet) of an IP address or subnet mask.
 *
 * @param {string} ip
 */
function not(ip) {
  const buff = toBuffer(ip);
  for (let i = 0; i < buff.length; i++) {
    buff[i] = 0xff ^ buff[i];
  }
  return toString(buff);
}

/**
 * Get the bitwise OR of two IP addresses
 * (usually an IP address and a subnet mask).
 *
 * @param {string} _a
 * @param {string} _b
 */
function or(_a, _b) {
  const a = toBuffer(_a);
  const b = toBuffer(_b);

  // same protocol
  if (a.length === b.length) {
    for (let i = 0; i < a.length; ++i) {
      a[i] |= b[i];
    }
    return toString(a);

  // mixed protocols
  }
  let buff = a;
  let other = b;
  if (b.length > a.length) {
    buff = b;
    other = a;
  }

  const offset = buff.length - other.length;
  for (let i = offset; i < buff.length; ++i) {
    buff[i] |= other[i - offset];
  }

  return toString(buff);
}

/**
 * Check two IP address are the same.
 *
 * @param {string} ip1
 * @param {string} ip2
 */
function isEqual(ip1, ip2) {
  let a = toBuffer(ip1);
  let b = toBuffer(ip2);

  // Same protocol
  if (a.length === b.length) {
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  // Swap
  if (b.length === 4) {
    [a, b] = [b, a];
  }

  // a - IPv4, b - IPv6
  for (let i = 0; i < 10; i++) {
    if (b[i] !== 0) return false;
  }

  const word = b.readUInt16BE(10);
  if (word !== 0 && word !== 0xffff) return false;

  for (let i = 0; i < 4; i++) {
    if (a[i] !== b[i + 12]) return false;
  }

  return true;
}

/**
 * Check whether an IP is within a private IP address range.
 *
 * @param {string} ip
 */
function isPrivate(ip) {
  return /^(::f{4}:)?10\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i
    .test(ip)
    || /^(::f{4}:)?192\.168\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(ip)
    || /^(::f{4}:)?172\.(1[6-9]|2\d|30|31)\.([0-9]{1,3})\.([0-9]{1,3})$/i
      .test(ip)
    || /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(ip)
    || /^(::f{4}:)?169\.254\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(ip)
    || /^f[cd][0-9a-f]{2}:/i.test(ip)
    || /^fe80:/i.test(ip)
    || /^::1$/.test(ip)
    || /^::$/.test(ip);
}

/**
 * Check whether an IP is within a public IP address range
 *
 * @param {string} addr
 */
function isPublic(addr) {
  return !isPrivate(addr);
}

/**
 * Check whether an IP is a loopback address.
 * @param {string} ip
 */
function isLoopback(ip) {
  return /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/
    .test(ip)
    || /^fe80::1$/.test(ip)
    || /^::1$/.test(ip)
    || /^::$/.test(ip);
}

/**
 * Get the loopback address for an IP family
 * @param {string | number} [family]
 * The family can be either "ipv4" or "ipv6". Default: "ipv4".
 */
function loopback(family) {
  //
  // Default to `ipv4`
  //
  family = _normalizeFamily(family);

  if (family !== 'ipv4' && family !== 'ipv6') {
    throw new Error('family must be ipv4 or ipv6');
  }

  return family === 'ipv4' ? '127.0.0.1' : 'fe80::1';
}

/**
 * Returns the address for the network interface on the current system with
 * the specified `name`:
 *   * String: First `family` address of the interface.
 *             If not found see `undefined`.
 *   * 'public': the first public ip address of family.
 *   * 'private': the first private ip address of family.
 *   * undefined: First address with `ipv4` or loopback address `127.0.0.1`.
 *
 * @param {string|'public'|'private'} [name]
 * The name can be any named interface, or 'public' or 'private'.
 *
 * @param {'ipv4'|'ipv6'|4|6} family
 * The family can be either "ipv4" or "ipv6". Default: "ipv4".
 *
 */
function address(name, family = 'ipv4') {
  const interfaces = networkInterfaces();

  //
  // Default to `ipv4`
  //
  family = _normalizeFamily(family);

  //
  // If a specific network interface has been named,
  // return the address.
  //
  if (name && name !== 'private' && name !== 'public') {
    const res = interfaces[name].filter((details) => {
      const itemFamily = _normalizeFamily(details.family);
      return itemFamily === family;
    });
    if (res.length === 0) {
      return undefined;
    }
    return res[0].address;
  }

  const all = Object.keys(interfaces).map((nic) => {
    //
    // Note: name will only be `public` or `private`
    // when this is called.
    //
    const addresses = interfaces[nic].filter((details) => {
      details.family = _normalizeFamily(details.family);
      if (details.family !== family || isLoopback(details.address)) {
        return false;
      } if (!name) {
        return true;
      }

      return name === 'public' ? isPrivate(details.address)
        : isPublic(details.address);
    });

    return addresses.length ? addresses[0].address : undefined;
  }).filter(Boolean);

  return all.length ? all[0] : loopback(family);
}

/**
 * Convert a string IPv4 IP address to the equivalent long numeric value.
 *
 * @param {string} ip
 */
function toLong(ip) {
  let ipl = 0;
  ip.split('.').forEach((octet) => {
    ipl <<= 8;
    ipl += +octet;
  });
  return ipl >>> 0;
}

/**
 * Convert an IPv4 IP address from its the long numeric value to a string.
 *
 * @param {number} ipl
 */
function fromLong(ipl) {
  return `${ipl >>> 24}.${
    ipl >> 16 & 255}.${
    ipl >> 8 & 255}.${
    ipl & 255}`;
}

export {
  address,
  cidr,
  cidrSubnet,
  fromLong,
  fromPrefixLen,
  isEqual,
  isLoopback,
  isPrivate,
  isPublic,
  isV4Format,
  isV6Format,
  loopback,
  _mask as mask,
  not,
  or,
  subnet,
  toBuffer,
  toLong,
  toString
};