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
});
