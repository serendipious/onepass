crypto = require 'crypto'

module.exports = class PassUtils
  # Generator Tokens
  SPECIALS = '!@#$%^&*()_+{}:"<>?\|[];\',./`~'
  LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
  UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  NUMBERS = '0123456789'
  ALL = "#{SPECIALS}#{LOWERCASE}#{UPPERCASE}#{NUMBERS}"

  @generatePassword: (passLength = 32) ->
    return crypto
      .pseudoRandomBytes(passLength)
      .toString('base64')

  @hashPassword: (password, salt) ->
    # Create Hash Function
    hasher = crypto.createHash 'sha256'
    # Hash Password
    hashedPassword = ''
    hasher.update password, 'utf8', 'hex'
    hashedPassword += hasher.digest 'hex'
    return hashedPassword

  @encrypt: (keychain, password) ->
    # Hash password
    hashedPassword = PassUtils.hashPassword(password)
    # Create Cipher
    cipher = crypto.createCipher 'AES256', hashedPassword
    # Encrypt Keychain
    encryptedKeyChain = ''
    encryptedKeyChain += cipher.update keychain, 'utf8', 'hex'
    encryptedKeyChain += cipher.final 'hex'
    return encryptedKeyChain

  @decrypt: (encryptedKeyChain, password) ->
    # Hash password
    hashedPassword = PassUtils.hashPassword(password)
    # Create Decipher
    decipher = crypto.createDecipher 'aes256', hashedPassword
    # Decrypt Keychain
    decryptedKeyChain = ''
    decryptedKeyChain += decipher.update encryptedKeyChain, 'hex', 'utf8'
    decryptedKeyChain += decipher.final 'utf8'
    return decryptedKeyChain


# String.prototype.pick = function(min, max) {
#     var n, chars = '';

#     if (typeof max === 'undefined') {
#         n = min;
#     } else {
#         n = min + Math.floor(Math.random() * (max - min));
#     }

#     for (var i = 0; i < n; i++) {
#         chars += this.charAt(Math.floor(Math.random() * this.length));
#     }

#     return chars;
# };


# // Credit to @Christoph: http://stackoverflow.com/a/962890/464744
# String.prototype.shuffle = function() {
#     var array = this.split('');
#     var tmp, current, top = array.length;

#     if (top) while (--top) {
#         current = Math.floor(Math.random() * (top + 1));
#         tmp = array[current];
#         array[current] = array[top];
#         array[top] = tmp;
#     }

#     return array.join('');
# };

# // Generator Tokens
# var specials = '!@#$%^&*()_+{}:"<>?\|[];\',./`~';
# var lowercase = 'abcdefghijklmnopqrstuvwxyz';
# var uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
# var numbers = '0123456789';
# var all = specials + lowercase + uppercase + numbers;

# // Password Generator
# function generatePassword() {
#   var password = '';
#   password += specials.pick(10);
#   password += lowercase.pick(10);
#   password += uppercase.pick(10);
#   password += all.pick(3, all.length);
#   password = password.shuffle();
#   return password;
# }


# $('#generate-pass').click(function(e) {
#   $('#pass').text(generatePassword());
# });


