var ip = require('..'),
    assert = require('assert');

describe('IP library for node.js', function() {
  describe('toBuffer()/toString() methods', function() {
    it('should convert to buffer IPv4 address', function() {
      var buf = ip.toBuffer('127.0.0.1');
      assert.equal(buf.toString('hex'), '7f000001');
      assert.equal(ip.toString(buf), '127.0.0.1');
    });

    it('should convert to buffer IPv6 address', function() {
      var buf = ip.toBuffer('::1');
      assert(/(00){15,15}01/.test(buf.toString('hex')));
      assert.equal(ip.toString(buf), '::1');
      assert.equal(ip.toString(ip.toBuffer('1::')), '1::');
      assert.equal(ip.toString(ip.toBuffer('abcd::dcba')), 'abcd::dcba');
    });
  });

  describe('not() method', function() {
    it('should reverse bits in address', function() {
      assert.equal(ip.not('255.255.255.0'), '0.0.0.255');
    });
  });

  describe('mask() method', function() {
    it('should mask bits in address', function() {
      assert.equal(ip.mask('192.168.1.134', '255.255.255.0'), '192.168.1.0');
      assert.equal(ip.mask('192.168.1.134', '::ffff:ff00'), '::ffff:c0a8:100');
    });
  });

  describe('isEqual() method', function() {
    it('should check if addresses are equal', function() {
      assert(ip.isEqual('127.0.0.1', '::7f00:1'));
      assert(!ip.isEqual('127.0.0.1', '::7f00:2'));
      assert(ip.isEqual('127.0.0.1', '::ffff:7f00:1'));
      assert(!ip.isEqual('127.0.0.1', '::ffaf:7f00:1'));
    });
  });
  

  describe('isPrivate() method', function() {
    it('should check if an address is localhost', function() {
      assert.equal(ip.isPrivate('127.0.0.1'), true);
    });
    
    it('should check if an address is from a 192.168.x.x network', function() {
      assert.equal(ip.isPrivate('192.168.0.123'), true);
      assert.equal(ip.isPrivate('192.168.122.123'), true);
      assert.equal(ip.isPrivate('192.162.1.2'), false);
    });
    
    it('should check if an address is from a 172.16.x.x network', function() {
      assert.equal(ip.isPrivate('172.16.0.5'), true);
      assert.equal(ip.isPrivate('172.16.123.254'), true);
      assert.equal(ip.isPrivate('171.16.0.5'), false);
    });
    
    it('should check if an address is from a 169.254.x.x network', function() {
      assert.equal(ip.isPrivate('169.254.2.3'), true);
      assert.equal(ip.isPrivate('169.254.221.9'), true);
      assert.equal(ip.isPrivate('168.254.2.3'), false);
    });
    
    it('should check if an address is from a 10.x.x.x network', function() {
      assert.equal(ip.isPrivate('10.0.2.3'), true);
      assert.equal(ip.isPrivate('10.1.23.45'), true);
      assert.equal(ip.isPrivate('12.1.2.3'), false);
    });
    
    it('should check if an address is from a private IPv6 network', function() {
      assert.equal(ip.isPrivate('fe80::f2de:f1ff:fe3f:307e'), true);
    });
    
    it('should check if an address is from the internet', function() {
      assert.equal(ip.isPrivate('165.225.132.33'), false); // joyent.com
    });
  });
});
