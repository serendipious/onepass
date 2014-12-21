###
MP := Master Password
For a random account:

   Ux := Username
   Px := Strong password generated
=> onepass_keychain = AES256( raw_keychain, keychain_pass )
    Where: keychain_pass := SHA256( MP, crypto-strong-pseudo-random-bits )

###

_         = require 'lodash'
fs        = require 'fs'
sync      = require 'sync'
read      = require 'read'
program   = require 'commander'
ascli     = require 'ascli'
debug     = require 'debug'

PassUtils = require "#{__dirname}/onepass-utils"
cli       = ascli.app('onepass')
log       = debug('onepass')

# Enable all log namespaces
debug.enable '*'

# Use keychain location from env if ONEPASS_PATH is set
# Else use the user's home and create a keychain there.
keychain_location = "#{process.env.ONEPASS_PATH or process.env.HOME}/.onepass_keychain"

KEYCHAIN_READ_ERROR_MSG = """
  Keychain was locked and could not be opened. Possible Reasons are:
    * The master password you entered didn't match the one used before (Use correct master password)
    * There is a bug in onepass (File a bug here: http://onepassbug.com)
    * You are not the account owner (Stop snooping around)
"""

co_routine = (fn) ->
  return (env, options) ->
    sync ->
      try
        do fn
      catch e
        e.message ||= 'Unknown Failure'
        e.stack ||= 'N/A'
        error_message = """
          Something Went Wrong.
            * Possible Cause: #{e.message}
            * Stack Trace: #{e.stack}
        """
        cli.fail error_message, -1



program
  .version('0.0.1')
  .usage('[command] [options]')
  .option '-l, --location <location>', 'Location of keychain on disk', (location) ->
    if fs.existsSync location
      log "Setting location to #{location}"
      keychain_location = location or DEFAULT_KEYCHAIN_LOCATION
    else
      cli.fail "Keychain location #{location} is invalid"



program
  .command('put')
  .description('Creates/Updates account in keychain')
  .action co_routine (env, options) ->
    account_id = read.sync read, prompt: 'Enter An Account Key:'
    username = read.sync read, prompt: 'Enter Username:'
    master_password = read.sync read, prompt: 'Enter Master Password:', silent: true

    log "Generating Keychain"
    log "account_id = #{account_id}"
    log "username = #{username}"
    log "master_password = #{master_password}"

    random_password = do PassUtils.generatePassword

    hashed_account_id = PassUtils.hashPassword(account_id)
    account_keychain_location = "#{keychain_location};#{hashed_account_id}"

    # keychain = new Object
    # Read existing keychain if one exists
    if fs.existsSync account_keychain_location
      try
        encrypted_keychain = fs.readFileSync account_keychain_location, 'HEX'
        keychain = JSON.parse PassUtils.decrypt(encrypted_keychain, master_password)
      catch e
        cli.fail KEYCHAIN_READ_ERROR_MSG, -1
    else
      log "No Keychain located. Creating a new one ..."

    # keychain[account_id] = { username, random_password }
    keychain = { username, random_password }
    encrypted_keychain = PassUtils.encrypt JSON.stringify(keychain), master_password
    fs.writeFileSync account_keychain_location, encrypted_keychain, 'HEX'
    cli.ok "Keychain Created Successfully! at #{account_keychain_location}"


program
  .command('get')
  .description('Retrieves account credentials in keychain')
  .action co_routine (env, options) ->
    account_id = read.sync read, prompt: 'Enter An Account Key:'
    master_password = read.sync read, prompt: 'Enter Master Password:', silent: true

    hashed_account_id = PassUtils.hashPassword(account_id)
    account_keychain_location = "#{keychain_location};#{hashed_account_id}"

    log "Retrieving Keychain for account #{account_id}"
    if fs.existsSync account_keychain_location
      try
        encrypted_keychain = fs.readFileSync account_keychain_location, 'HEX'
        keychain = JSON.parse PassUtils.decrypt(encrypted_keychain, master_password)
      catch e
        cli.fail KEYCHAIN_READ_ERROR_MSG, -1
    else
      cli.fail "No Keychain located."

    # account = keychain[account_id]
    if not keychain?
      cli.fail "No Account Credentials Stored for id = #{account_id}"
    else
      { username, random_password } = keychain
      cli.ok """
        Here are credentials for account #{account_id}:

          * username = #{username}
          * password = #{random_password}
      """

# Set default arguments if nothing is provided
if process.argv.length <= 2
  process.argv.push('--help')

log "CLI arguments provided:\n"
log "\t#{process.argv}"

# Run CLI program
program.parse process.argv
