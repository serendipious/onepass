// Generated by CoffeeScript 1.7.1
(function() {
  var PassUtils, crypto;

  crypto = require('crypto');

  module.exports = PassUtils = (function() {
    var ALL, LOWERCASE, NUMBERS, SPECIALS, UPPERCASE;

    function PassUtils() {}

    SPECIALS = '!@#$%^&*()_+{}:"<>?\|[];\',./`~';

    LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';

    UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    NUMBERS = '0123456789';

    ALL = "" + SPECIALS + LOWERCASE + UPPERCASE + NUMBERS;

    PassUtils.generatePassword = function(passLength) {
      if (passLength == null) {
        passLength = 32;
      }
      return crypto.pseudoRandomBytes(passLength).toString('base64');
    };

    PassUtils.hashPassword = function(password, salt) {
      var hashedPassword, hasher;
      hasher = crypto.createHash('sha256');
      hashedPassword = '';
      hasher.update(password, 'utf8', 'hex');
      hashedPassword += hasher.digest('hex');
      return hashedPassword;
    };

    PassUtils.encrypt = function(keychain, password) {
      var cipher, encryptedKeyChain, hashedPassword;
      hashedPassword = PassUtils.hashPassword(password);
      cipher = crypto.createCipher('AES256', hashedPassword);
      encryptedKeyChain = '';
      encryptedKeyChain += cipher.update(keychain, 'utf8', 'hex');
      encryptedKeyChain += cipher.final('hex');
      return encryptedKeyChain;
    };

    PassUtils.decrypt = function(encryptedKeyChain, password) {
      var decipher, decryptedKeyChain, hashedPassword;
      hashedPassword = PassUtils.hashPassword(password);
      decipher = crypto.createDecipher('aes256', hashedPassword);
      decryptedKeyChain = '';
      decryptedKeyChain += decipher.update(encryptedKeyChain, 'hex', 'utf8');
      decryptedKeyChain += decipher.final('utf8');
      return decryptedKeyChain;
    };

    return PassUtils;

  })();

}).call(this);