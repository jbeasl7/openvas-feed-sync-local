# SPDX-FileCopyrightText: Nicolas Pouvesle
# SPDX-FileCopyrightText: New code / functions since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

global_var _ssh_banner;
global_var _ssh_error;
global_var _last_libssh_sess;
global_var ssh_host_key_algos, ssh_expired_pw_text;

# Global vars to avoid that we're repeatedly asking redis for something we already know.
global_var __ssh_elevate_privs_enabled_nd_working, __ssh_kb_privlogin, __ssh_kb_privpassword;

ssh_host_key_algos = make_list( "ssh-rsa",
                                "ssh-dss",
                                "ecdsa-sha2-nistp256",
                                "ecdsa-sha2-nistp384", # Available in libssh >= 0.6.4
                                "ecdsa-sha2-nistp521", # Available in libssh >= 0.6.4
                                "ssh-ed25519", # Available in libssh >= 0.7.0
                                "rsa-sha2-256", # Available in libssh >= 0.8.3
                                "rsa-sha2-512" ); # Available in libssh >= 0.8.3

# nb: Those are possible/known text pattern (used mainly by ssh_authorization.nasl) which
# can be used to check a SSH response against to see if the used credentials for the SSH
# Login has expired. Taken from: Ubuntu 16.04, Debian 4.0, SLES 11, SLES 12, CentOS 7.4, Oracle Linux 7.4, SunOS 5.11).
# TODO: Verify / add additional pattern from different distros
ssh_expired_pw_text = make_list( "You are required to change your password immediately", # nb: This has the reason like e.g. '(password aged)' or '(root enforced)' at the line end which wasn't added here...
                                 "WARNING: Your password has expired.",
                                 "You must change your password now and login again!",
                                 "(current) UNIX password:",
                                 "Enter new UNIX password:",
                                 # nb: The next two are from SLES 11 but our ssh_cmd() in ssh_authorization.nasl currently doesn't return this text
                                 # because SLES 11 is using "keyboard-interactive" and the password prompt is caught earlier directly in the SSH
                                 # functions of the scanner.
                                 "Password change requested. Choose a new password.",
                                 "Old Password:",
                                 # This one is from SunOS 5.11. It has also a two additional pattern from the list above but.
                                 "Enter existing login password:" );

function kb_ssh_login() {
  return string( get_kb_item( "Secret/SSH/login" ) );
}

function kb_ssh_password() {
  return string( get_kb_item( "Secret/SSH/password" ) );
}

function kb_ssh_privatekey() {
  return string( get_kb_item( "Secret/SSH/privatekey" ) );
}

function kb_ssh_publickey() {
  return string( get_kb_item( "Secret/SSH/publickey" ) );
}

function kb_ssh_passphrase() {
  return string( get_kb_item( "Secret/SSH/passphrase" ) );
}

function kb_ssh_transport() {

  local_var r;
  r = get_preference( "auth_port_ssh" );
  if ( r )
    return int( r );

  r = get_kb_item( "Services/ssh" );

  if ( r )
    return int( r );
  else
    return 22;
}

# @brief Returns a possible existing "SSH privilege login name" (saved by
#        ssh_authorization_init.nasl) from the KB.
#
# @return A string containing the SSH privilege login name or an empty string if
#         none available.
#
function ssh_kb_privlogin() {

  local_var login;
  # nb: __ssh_kb_privlogin is a global var

  if( ! isnull( __ssh_kb_privlogin ) ) {
    login = string( __ssh_kb_privlogin );
  } else {
    login = string( get_kb_item( "Secret/SSH/privlogin" ) );
    __ssh_kb_privlogin = login;
  }
  return login;
}

# @brief Returns a possible existing "SSH privilege password" (saved by ssh_authorization_init.nasl)
#        from the KB.
#
# @return A string containing the SSH privilege password or an empty string if none available.
#
function ssh_kb_privpassword() {

  local_var password;
  # nb: __ssh_kb_privpassword is a global var

  if( ! isnull( __ssh_kb_privpassword ) ) {
    password = string( __ssh_kb_privpassword );
  } else {
    password = string( get_kb_item( "Secret/SSH/privpassword" ) );
    __ssh_kb_privpassword = password;
  }
  return password;
}

# @brief Get the MD5 SSH Host Key.
#
# @param sess_id The SSH session id of the SSH connection to the target host.
#
# @return The SSH Host Key as a data block on success or NULL on error.
#
function ssh_get_server_host_key( sess_id ) {

  if( isnull( sess_id ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#sess_id#-#get_server_host_key" );
    return NULL;
  }

  if( sess_id && int( sess_id ) > 0 )
    _last_libssh_sess = sess_id;

  return ssh_get_host_key( _last_libssh_sess );
}

#-----------------------------------------------------------------#
# Set SSH debugging error msg                                     #
#-----------------------------------------------------------------#
function ssh_set_error( msg ) {

  local_var msg;

  _ssh_error = msg;
}

#-----------------------------------------------------------------#
# Get SSH debugging error msg                                     #
#-----------------------------------------------------------------#
function ssh_get_error() {
  return _ssh_error;
}

#-----------------------------------------------------------------#
# Get SSH supported authentication methods
#-----------------------------------------------------------------#
function ssh_get_supported_authentication( sess_id ) {

  local_var sess_id;

  if( isnull( sess_id ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#sess_id#-#ssh_get_supported_authentication" );
    return NULL;
  }

  if( sess_id && int( sess_id ) > 0 )
    _last_libssh_sess = sess_id;

  return ssh_get_auth_methods( _last_libssh_sess );
}

#-----------------------------------------------------------------#
# Init packet sequence number and channel number                  #
#-----------------------------------------------------------------#
function init() {
  _ssh_banner = "";
  _ssh_error = "";
  _last_libssh_sess = 0;
}

#-----------------------------------------------------------------#
# Reads a SSH packet (comes from smb_nt.inc)                      #
#-----------------------------------------------------------------#
function ssh_recv(socket, length) {

  local_var socket, length;
  local_var header, len, trailer, ret;

  header = recv( socket:socket, length:4, min:4 );
  if( strlen( header ) < 4 )
    return( NULL );

  len = ntol( buffer:header, begin:0 );
  if( ( len == 0 ) || ( len > 32768 ) )
    return( header );

  trailer = recv( socket:socket, length:len, min:len );
  if( strlen( trailer ) < len )
    return( NULL );

  # SSH servers can send IGNORE (code 2) or BANNER (code 53) msg
  ret = ord( trailer[1] );
  if( ( ret == 2 ) || ( ret == 53 ) ) {
    if( ret == 53 )
      _ssh_banner += getstring( buffer:trailer, pos:2 );

    return ssh_recv( socket:socket, length:length );
  }

  return strcat( header, trailer );
}

# @brief Waits for the server identification string, and sends our own
#        identification string.
#
# @param socket The socket for the connection to the remote SSH service.
#
# @return The response to the SSH identification exchange request or 0 if
#         if not all required parameters are passed, no connection could
#         be opened to the target, the remote service is no SSH service or
#         doesn't support version SSHv2.
#
function ssh_exchange_identification(socket) {

  local_var socket;
  local_var buf, sshversion, num, vt_strings, prot;

  if(!socket) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ssh_exchange_identification");
    return;
  }

  buf = recv_line(socket:socket, length:1024);
  if(!buf) {
    ssh_set_error(msg:"The scanner did not receive the server's version.");
    return 0;
  }

  if(!ssh_verify_server_ident(data:buf)) {
    ssh_set_error(msg:"Remote service is not a valid SSH service.");
    return 0;
  }

  sshversion = split(buf, sep:"-", keep:FALSE);
  num = split(sshversion[1], sep:".", keep:FALSE);

  # version supported = 2 & 1.99
  if((num[0] != 2) && !((num[0] == 1) && (num[1] == 99))) {
    ssh_set_error(msg:"The scanner only supports SSHv2.");
    return 0;
  }

  # We use 2.0 protocol
  vt_strings = get_vt_strings();
  prot = "SSH-2.0-" + vt_strings["default"] + raw_string(0x0a);
  send(socket:socket, data:prot);

  if('\r\n' >< buf)
    buf = buf - '\r\n';
  else
    buf = buf - '\n';

  # all is correct
  return buf;
}

#-----------------------------------------------------------------#
# Get string (length,string)                                      #
#-----------------------------------------------------------------#
function getstring( buffer, pos ) {

  local_var buffer, pos;
  local_var buf_len, buf;

  buf_len = ntol( buffer:buffer, begin:pos );
  buf = substr( buffer, pos + 4, pos + 4 + buf_len - 1 );
  return buf;
}

# @brief Login to SSH server
#
# @param socket     The existing TCP socket for the connection to the SSH server.
# @param login      The login
# @param password   The password
# @param priv       The (optional) SSH private key
# @param passphrase The (optional) passphrase for the given SSH private key
# @param keytype    The (optional) type of the SSH key
#
# @return 0 if the login was successful, -1 if not all required parameters were passed or
#         the connection/login has failed and -2 if the SSH service is only supporting "none"
#         authentication.

function ssh_login( socket, login, password, priv, passphrase, keytype ) {

  local_var socket, login, password, priv, passphrase, keytype;
  local_var oid, sess, auth_successful;

  if( ! socket ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ssh_login" );
    return -1;
  }

  if( isnull( login ) ) {
    oid = get_script_oid();
    if( oid != "1.3.6.1.4.1.25623.1.0.100259" ) # ssh_proto_version.nasl is not passing a login to ssh_login. TODO: Check this
      set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#login#-#ssh_login" );
  }

  sess = ssh_connect( socket:socket, keytype:keytype );
  if( ! sess )
    return -1;

  _last_libssh_sess = sess;

  auth_successful = ssh_userauth( sess, login:login, password:password, privatekey:priv, passphrase:passphrase );

  # nb: ssh_userauth() is returning 0 on success but everything else like -1, 1 or NULL is an error
  # or failure. In the initial implementation of this function "if(ssh_userauth())" was used below
  # to cover all != 0 cases but the NULL case was missed which is now also checked below.
  if( isnull( auth_successful ) || auth_successful )
    return -1;

  # none method fix
  ssh_supported_authentication = ssh_get_supported_authentication( sess_id:sess );
  if( ssh_supported_authentication == "" ||
      ssh_supported_authentication == "none" ||
      ord( ssh_supported_authentication ) == "0" ) {
    return -2;
  }
  # end none method fix

  return 0;
}

function del_esc_seq( data ) {

  local_var data;

  data = ereg_replace( pattern:'\x1b\x5b[0-9;]*[mK]', replace:'', string:data );
  data = ereg_replace( pattern:'\x1b\x3e', replace:'', string:data );
  data = ereg_replace( pattern:'[\r|\x07|\x1b|\x08|\\[|\x0c]', replace:'', string:data );

  return data;
}

# @brief Reads data from an already opened SSH connection / shell
#
# @param sess    The SSH session id of the SSH connection to the target host.
# @param pattern A regex pattern to match the response against. Once a match was found all data
#                received until this match (including the match) is returned.
# @param timeout An (optional) timeout in seconds. Once this is reached all data received up to this
#                timeout is returned. Defaults to 15. If set to 0 all data is returned directly once
#                no more data has been received.
# @param retry   An (optional) amount of retries to try if no data was received from the SSH
#                connection. Defaults to 3.
#
# @return The received data, NULL if no data was received or FALSE if the "sess" parameter wasn't
#         given.
#
function ssh_read_from_shell( sess, pattern, timeout, retry ) {

  local_var sess, pattern, timeout, retry;
  local_var x, buf, len, t, ret;

  if( ! sess ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#sess#-#ssh_read_from_shell" );
    return FALSE;
  }

  if( isnull( timeout ) )
    timeout = 15;

  if( isnull( retry ) )
    retry = 3;

  x = 1;

  while( TRUE ) {

    buf = del_esc_seq( data:ssh_shell_read( sess ) );

    len = strlen( buf );
    t++;

    if( len > 0 ) {
      ret += buf;
      x = 1;
    } else {
      if( x++ >= retry )
        return ret;
    }

    if( pattern && ret )
      if( eregmatch( pattern:pattern, string:ret ) )
        return ret;

    if( t >= timeout )
      return ret;

    sleep( 1 );

    if( "Press Enter to continue" >< ret || "<--- More --->" >< ret || # nb: Unknown devices / software / targets
        "--More" >< ret || # nb: Seen on at least Cisco WLC like e.g. "--More-- or (q)uit"
        egrep( string:ret, pattern:"^#?\s*-+\s*[Mm]ore\s*-+", icase:FALSE ) # nb: Huawei VRP (Yunshan)
      )
      ssh_shell_write( sess, cmd:'\n' );
  }
  return ret;
}

function ssh_cmd_pty( sess, cmd, pattern, timeout, retry, clear_buffer ) {

  local_var sess, cmd, pattern, timeout, retry, clear_buffer;
  local_var extra_cmd, c, ret;

  if( ! cmd ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cmd#-#ssh_cmd_pty" );
    return FALSE;
  }

  if( ! sess )
    sess = _last_libssh_sess;

  if( ! sess || int( sess ) < 1 )
    return FALSE;

  if( ! sess = ssh_shell_open( sess ) )
    return FALSE;

  if( isnull( timeout ) )
    timeout = 15;

  if( isnull( retry ) )
    retry = 3;

  if( extra_cmd = get_kb_item( "ssh/send_extra_cmd" ) ) {
    ssh_shell_write( sess, cmd:extra_cmd );
    sleep( 5 );
  }

  if( isnull( clear_buffer ) ) {
    if( get_kb_item( "ssh/force/clear_buffer" ) )
      clear_buffer = TRUE;
  }

  # Clear the buffer before sending the command. This is needed for Cisco NGIPS for example. Without
  # clearing the buffer you didn't get anything back for the executed command. I'd only see this
  # against Cisco NGIPS currently. Do not use "clear_buffer" in gather-package-list.nasl for the
  # "uname" command. We need the complete buffer there...
  if( clear_buffer ) {
    while( TRUE ) {
      c = ssh_read_from_shell( sess:sess, timeout:3, retry:3 );
      if( strlen( c ) <= 0 )
        break;
    }
  }

  ssh_shell_write( sess, cmd:cmd + '\n' );
  sleep( 1 );

  ret = ssh_read_from_shell( sess:sess, pattern:pattern, timeout:timeout, retry:retry );
  ssh_shell_close( sess );

  if( ! ret )
    return FALSE;

  ret = str_replace( string:ret, find:cmd + '\n', replace:"" );

  return( ret );
}

# @brief Execute a command on a remote SSH server
#
# @param socket                   The existing TCP socket for the connection to the SSH server.
# @param cmd                      The command to send.
# @param timeout                  An (optional) timeout in seconds. Once this is reached all
#                                 data received up to this timeout is returned. Defaults to 15.
#                                 Note: This timeout value is only used if "pty" is set to "TRUE".
# @param nosh                     If set to "TRUE" no "/bin/sh -c" will be prepended to all commands.
# @param nosu                     If set to "TRUE" no evaluation if "su -" should be prepended to
#                                 all commands is done.
# @param return_errors            If set to "TRUE" the function will return known errors (e.g. not found binaries).
# @param return_linux_errors_only If set to "TRUE" only some specific linux SSH command related errors are returned.
# @param pty                      If set to "TRUE" a PTY (Pseudo terminal) is used to send and receive the data.
# @param pattern                  A regex pattern to match the response against. Once a match was
#                                 found all data received until this match (including the match)
#                                 is returned. Note: This pattern is only used if "pty" is set to "TRUE".
# @param retry                    An (optional) amount of retries to try if no data was received
#                                 from the SSH connection. Defaults to 3.
#                                 Note: This retry value is only used if "pty" is set to "TRUE".
# @param clear_buffer             If set to "TRUE" any received data from the SSH server is cleared before sending
#                                 the command and receiving the response to it.
# @param force_reconnect          If set to "TRUE" a re-connect to the SSH server is done before sending the command.
# @param ignore_force_pty         If set to "TRUE" the internal "ssh/force/pty" KB key is ignored.
#
# @return The received data from the SSH server (could be NULL/empty as well) or NULL if no "cmd" and/or no "socket"
#         parameter was passed or no connection could be established to the SSH server.

function ssh_cmd( socket, cmd, timeout, nosh, nosu, return_errors, return_linux_errors_only, pty, pattern, retry, clear_buffer, force_reconnect, ignore_force_pty ) {

  local_var socket, cmd, timeout, nosh, nosu, return_errors, return_linux_errors_only, pty, pattern, retry, clear_buffer, force_reconnect, ignore_force_pty;
  local_var elevate_privs, use_su, su_user, nolang_sh, debug_enabled, debug_str, sess, ret_ssh_buf, err;

  if( ! cmd ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cmd#-#ssh_cmd" );
    return;
  }

  if( ! socket ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ssh_cmd" );
    return;
  }

  elevate_privs = ssh_elevate_privs_enabled_nd_working();

  if( ! nosu ) {
    use_su = get_kb_item( "ssh/lsc/use_su" );
    if( use_su && "yes" >< use_su &&
        ! elevate_privs ) { # Don't use su - when using second credential
      su_user = get_kb_item( "ssh/lsc/su_user" );
      # Using single quotes for the -c parameter loads the environmental variables
      # of the su user. Using single quotes makes the escaping of them to such a pain.
      cmd = str_replace( string:cmd, find:"'", replace:'\'"\'"\'' );
      cmd = "su - " + su_user + " -s /bin/bash -c '" + cmd + "'";
      # Don't use nosh with su option enabled
      nosh = TRUE;
    }
  }

  if( ! nosh ) {
    if( get_kb_item( "ssh/force/nosh" ) )
      nosh = TRUE; # NX-OS/IOS/Junos OS/F5
    else if( get_kb_item( "ssh/force/nolang_sh" ) )
      nolang_sh = TRUE; # pfSense, see description below
  }

  if( get_kb_item( "ssh/no_linux_shell" ) ) {
    nosh = TRUE;
    if( cmd =~ "^(/s?bin|cat |perl |cmd /|netstat |find |which |whereis |locate |dmidecode |grep |systemctl )" )
      return FALSE; # don't run find, which ... if target doesn't support it
  }

  if( ! nosh ) {
    cmd = str_replace( string:cmd, find:"'", replace:'"' );
    # nb: Special handling for e.g. pfSense which had returned the command but with a space in between the command
    # (e.g. 'u name -a' instead of 'uname -a' causing ssh_cmd_pty() to not remove this echo from the return value.
    if( nolang_sh )
      cmd = string( "/bin/sh -c ", "'", cmd, "'" );
    else
      cmd = string( "/bin/sh -c ", "'LANG=C; LC_ALL=C; ", cmd, "'" );
  }

  if( ! pty ) {
    if( ! ignore_force_pty && get_kb_item( "ssh/force/pty" ) )
      pty = TRUE;
  }

  # nb: Just some sane defaults for e.g. the debug logging below
  if( isnull( pty ) )
    pty = FALSE;
  if( isnull( nosh ) )
    nosh = FALSE;

  debug_enabled = get_kb_item( "global_settings/ssh/debug" );
  if( debug_enabled ) {
    debug_str = '\n---------------------------------------------------------\n' +
                'SSH DEBUG:\n' +
                'IP:   ' + get_host_ip() + '\n' +
                'PTY:  ' + pty + '\n' +
                'NOSH: ' + nosh + '\n' +
                'CMD:  ' + cmd + '\n';
  }

  # At least Huawei VRP devices requires to re-open a clean SSH connection to get a response.
  if( get_kb_item( "ssh/force/reconnect" ) || force_reconnect ) {
    ssh_close_connection( socket:socket );
    socket = ssh_login_or_reuse_connection();
    if( ! socket ) {
      if( debug_enabled ) {
        debug_str += 'NOTE: Failed to reconnect to target host';
        debug_str += '\n---------------------------------------------------------';
        display( debug_str );
      }
      return;
    }
  }

  sess = ssh_session_id_from_sock( socket );
  if( sess ) {
    if( elevate_privs )
      ret_ssh_buf = ssh_cmd_with_su( sess:sess, cmd:cmd, pty:pty, pattern:pattern, timeout:timeout, retry:retry, clear_buffer:clear_buffer );
    else if( pty )
      ret_ssh_buf = ssh_cmd_pty( sess:sess, cmd:cmd, pattern:pattern, timeout:timeout, retry:retry, clear_buffer:clear_buffer );
    else {
      # Note: Setting stdout and stderr to 0 enables a compatibility mode to be bug compliant to the
      # NASL SSH code.
      ret_ssh_buf = ssh_request_exec( sess, cmd:cmd, stdout:0, stderr:0 );
    }

    ret_ssh_buf = chomp( ret_ssh_buf );

    if( ! ret_ssh_buf ) {
      if( debug_enabled && ! elevate_privs ) { # nb: ssh_cmd_with_su() has separate debug logging
        debug_str += 'RES:  (empty / no response)';
        debug_str += '\n---------------------------------------------------------';
        display( debug_str );
      }
      return NULL;
    }

    if( debug_enabled && ! elevate_privs )
      debug_str += '\nRES (before clean up):\n--- added separator start ---\n' + ret_ssh_buf + '\n--- added separator end   ---\n';

    ret_ssh_buf = ssh_clean_cmd_from_err( data:ret_ssh_buf );

    if( ! ret_ssh_buf ) {
      if( debug_enabled && ! elevate_privs ) {
        debug_str += 'RES:  (empty after clean up)';
        debug_str += '\n---------------------------------------------------------';
        display( debug_str );
      }
      return NULL;
    }

    if( debug_enabled && ! elevate_privs ) {
      debug_str += '\nRES (after clean up):\n--- added separator start ---\n' + ret_ssh_buf + '\n--- added separator end   ---\n';
      display( debug_str );
    }

    # nb: For specific appliances where no "/bin/sh" should be added to the commands
    if( "Cmd exec error" >< ret_ssh_buf ||
        "error: unknown command" >< ret_ssh_buf ||
        "Unknown command: " >< ret_ssh_buf ||
        "Invalid input detected" >< ret_ssh_buf ||
        ": No such command" >< ret_ssh_buf ||
        "-----unknown keyword " >< ret_ssh_buf ||
        "Unknown action 0" >< ret_ssh_buf || # Fortinet/FortiOS products
        "Line has invalid autocommand" >< ret_ssh_buf || # Cisco IOS with invalid autocommand configuration
        "Error: Unrecognized command found" >< ret_ssh_buf || # Huawei VRP
        "Invalid command" >< ret_ssh_buf || # HP iLO 100
        "is not a recognized command" >< ret_ssh_buf || # NetApp Data ONTAP 9.x
        "not found.  Type '?' for a list of commands" >< ret_ssh_buf || # NetApp Data ONTAP 7.x
        "Syntax Error: unexpected argument" >< ret_ssh_buf || # NX-OS/IOS/Junos OS/F5
        "> % Command not found" >< ret_ssh_buf || # Zyxel USG and similar
        # e.g.:
        # -> /bin/sh command not support now.
        # seen on Insyde SMASH-CLP System Management Shell (BMC related)
        ret_ssh_buf =~ "-> [^ ]+ command not support now\." ||
        # All three are Dell DRAC/iDRAC
        "COMMAND PROCESSING FAILED" >< ret_ssh_buf ||
        "COMMAND NOT RECOGNIZED" >< ret_ssh_buf ||
        "ERROR: Invalid command specified." >< ret_ssh_buf
      ) {

      set_kb_item( name:"ssh/force/nosh", value:TRUE );

      if( ! return_errors )
        return '';

      if( return_linux_errors_only )
        return '';
    }

    # Special cases for logging purposes in gb_authenticated_scan_lsc_ssh_login_consolidation.nasl
    # to log any "broken" binary calls throwing segmentation faults and similar. Note that this
    # needs to be placed above the check below because of the "No such file or directory" message
    # included here as well.
    #
    # e.g.:
    # ./$mybin: error while loading shared libraries: $mylib.so: cannot open shared object file: No such file or directory
    # ./$mybin: error while loading shared libraries: $mylib.so: file too short
    # ./$mybin: error while loading shared libraries: $mylib.so: internal error
    # Segmentation fault (core dumped)
    if( err = egrep( string:ret_ssh_buf, pattern:"(: error while loading shared libraries: |Segmentation fault \(core dumped\))", icase:TRUE ) ) {
      set_kb_item( name:"ssh/login/broken_binaries", value:chomp( cmd ) + "##----##----##" + chomp( err ) );
      if( ! return_errors )
        return '';
    }

    # e.g.:
    # /bin/sh: 1: /usr/share/bash-completion/completions/xfreerdp: Permission denied
    # grep: /usr/include/freetype2/freetype/freetype.h: No such file or directory
    # cat: cannot open /etc/turbolinux-release
    # vmware -v: /bin/sh: vmware:  not found (nb: Seen on AIX)
    #
    # e.g. rpm -q gpg-pubkey on e.g. CentOS 8:
    # package gpg-pubkey is not installed
    #
    # Some VTs might call "which" directly. At least on Debian a "which foo" is returning nothing /
    # is empty but some RPM based systems like SLES 15 or CentOS 7 are returning something like e.g.
    # below which needs to be covered as well:
    #
    # which: no foo in (/home/user/.local/bin:/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin)
    # /usr/bin/which: no foo in (/home/user/.local/bin:/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin)
    #
    # nb: There is one code path in gather-package-list.nasl requiring errors to be returned. Make
    # sure to update that one when adding new pattern here (if applicable).
    if( ret_ssh_buf =~ ": +not found" || ret_ssh_buf =~ ": +Permission denied" || ret_ssh_buf =~ ": +cannot open " || ret_ssh_buf =~ ": +can't cd to" ||
        ret_ssh_buf =~ "No such file or directory" || ret_ssh_buf =~ "command not found" || ret_ssh_buf =~ ": +Not a directory" ||
        ret_ssh_buf =~ "^package [^ ]+ is not installed$" || ret_ssh_buf =~ "which: +no [^ ]+ in \([^)]+\)" ) {
      if( ! return_errors )
        return '';
    }

    return chomp( ret_ssh_buf );
  } else {
    if( debug_enabled ) {
      debug_str += 'NOTE: Failed to open an SSH session to the target host';
      debug_str += '\n---------------------------------------------------------';
      display( debug_str );
    }
  }

  return NULL;
}

# @brief Returns if the "Elevate Privileges" feature has been enabled by the user including the info
#        if it was successful.
#
# @note Add a dependency to ssh_authorization.nasl which includes a check if elevating the
#       privileges (login/SSH/priv/failed KB key) is working.
#
# @return TRUE if the feature has been enabled and is working, FALSE otherwise.
#
function ssh_elevate_privs_enabled_nd_working() {

  local_var elevate_privs;
  # nb: __ssh_elevate_privs_enabled_nd_working is a global var

  if( ! isnull( __ssh_elevate_privs_enabled_nd_working ) ) {
    elevate_privs = __ssh_elevate_privs_enabled_nd_working;
  } else {
    if( ! get_kb_item( "login/SSH/priv/failed" ) && ssh_kb_privlogin() )
      elevate_privs = TRUE;
    else
      elevate_privs = FALSE;

    __ssh_elevate_privs_enabled_nd_working = elevate_privs;
  }
  return elevate_privs;
}

# @brief              Sends a command with the "Elevate Privileges" feature enabled (sending
#                     "su - USER" to the remote host and elevating privileges with a user-given
#                     password before sending the actual command).
#
# @param sess         The existing session to the SSH server.
# @param cmd          The command to send.
# @param pty          If set to "TRUE" the full PTY (Pseudo terminal) output is returned while
#                     receiving the data. Defaults to "FALSE" if not given.
# @param pattern      A regex pattern to match the response against. Once a match was found all data
#                     received until this match (including the match) is returned.
# @param timeout      An (optional) timeout in seconds. Once this is reached all data received up to
#                     this timeout is returned. Defaults to 15.
# @param retry        An (optional) amount of retries to try if no data was received from the SSH
#                     connection. Defaults to 3.
# @param clear_buffer If set to "TRUE" any received data from the SSH server is cleared before
#                     sending the command and receiving the response to it.
#
# @return The response to the sent command or FALSE if no connection to the remote host was
#         possible, no privileges could be elevated or no response (also if no response
#         was received matching the given pattern) was received.
#
function ssh_cmd_with_su( sess, cmd, pty, pattern, timeout, retry, clear_buffer ) {

  local_var sess, cmd, pty, pattern, timeout, retry, clear_buffer;
  local_var debug_enabled, debug_str, shell, priv_user, su_cmd, ret, priv_password, c, split_ret, _split_item;

  if( ! cmd ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cmd#-#ssh_cmd_with_su" );
    return FALSE;
  }

  if( ! sess )
    sess = _last_libssh_sess;

  if( ! sess || int( sess ) < 1 )
    return FALSE;

  if( isnull( pty ) )
    pty = FALSE;

  if( ! pty ) {
    # nb: If pty == FALSE we're defining our own shell prompt to be able to strip it away from the
    # response later / below more easily.
    cmd = 'export PS1="##greenbone-defined-shell-prompt##"; ' + cmd;
    # In a similar way we're clearing PROMPT_COMMAND because some systems (namely CentOS7/8 and
    # RHEL8) defining an own shell prompt in there via "printf". See the following for more info on
    # this command:
    # https://boxmatrix.info/wiki/Property:PROMPT_COMMAND
    # > If set, the value is interpreted as a command to execute before the printing of each primary prompt ('$PS1').
    # We're using "> /dev/null 2>&1" here because some systems might have defined "PROMPT_COMMAND"
    # as a readonly variable which would cause the following error returned:
    # bash: unset: PROMPT_COMMAND: cannot unset: readonly variable
    cmd = 'unset PROMPT_COMMAND > /dev/null 2>&1; ' + cmd;
  }

  debug_enabled = get_kb_item( "global_settings/ssh/debug" );
  if( debug_enabled ) {
    debug_str = '\n---------------------------------------------------------\n' +
                'SSH DEBUG ("Elevate Privileges" feature enabled):\n' +
                'IP:   ' + get_host_ip() + '\n' +
                'PTY:  ' + pty + '\n' +
                'CMD:  ' + cmd + '\n';
  }

  # Open interactive shell in open session. We always want to open the shell with pty:TRUE because
  # some systems are requiring this (for currently unknown reasons) if "su - USER" is used.
  # Such systems are responding with something like e.g. the following otherwise:
  # "su: must be run from a terminal"
  if( ! shell = ssh_shell_open( sess, pty:TRUE ) ) {
    if( debug_enabled ) {
      debug_str += 'NOTE: Failed to open interactive shell in open session';
      debug_str += '\n---------------------------------------------------------';
      display( debug_str );
    }
    return FALSE;
  }

  # nb: Shouldn't happen but we're still checking this just to be sure...
  if( ! priv_user = ssh_kb_privlogin() ) {
    ssh_shell_close( shell );
    return FALSE;
  }

  # nb: Defaults have been raised from 15 (for timeout) / 3 (for retry) because of truncated package
  # lists (dpkg/rpm calls) received within ssh_read_from_shell() / ssh_shell_read().
  if( isnull( timeout ) )
    timeout = 100;

  if( isnull( retry ) )
    retry = 10;

  # From "man stty":
  # "[-]echo echo input characters"
  # Using this command avoids that our sent command is echoed back to us on the opened PTY
  ssh_shell_write( shell, cmd:'stty -echo\n' );

  # send "su - USER" to open shell
  su_cmd = 'su - ' + priv_user + '\n';
  ssh_shell_write( shell, cmd:su_cmd );

  # Parse return for string "Password:"
  ret = ssh_read_from_shell( sess:shell, timeout:timeout, retry:retry );
  ret = chomp( ret );
  if( ! ret || "Password:" >!< ret ) {
    ssh_shell_close( shell );
    if( debug_enabled ) {
      debug_str += 'NOTE: Failed to read "Password:" string from response\n';
      if( ! ret )
        debug_str += 'RES:  (empty / no response)';
      else
        debug_str += 'RES:\n--- added separator start ---\n' + ret + '\n--- added separator end   ---';
      debug_str += '\n---------------------------------------------------------';
      display( debug_str );
    }
    return FALSE;
  }

  # nb: Shouldn't happen but we're still checking this just to be sure...
  if( ! priv_password = ssh_kb_privpassword() ) {
    ssh_shell_close( shell );
    return FALSE;
  }

  # Send password for privileged user
  ssh_shell_write( shell, cmd:priv_password + '\n' );

  if( isnull( clear_buffer ) ) {
    if( get_kb_item( "ssh/force/clear_buffer" ) )
      clear_buffer = TRUE;
  }

  # Clear buffer (if enabled) to remove all received data from server before sending the actual
  # command. If pty == FALSE we also need to clear this buffer so that the terminal output isn't
  # included in the response / return value below.
  if( clear_buffer || ! pty ) {
    while( TRUE ) {
      c = ssh_read_from_shell( sess:shell, timeout:3, retry:3 );
      if( strlen( c ) <= 0 )
        break;
    }
  }

  # Send the actual command passed in the "cmd" function parameter and retrieve the response.
  ssh_shell_write( shell, cmd:cmd + '\n' );
  sleep( 1 );

  ret = ssh_read_from_shell( sess:shell, timeout:timeout, retry:retry, pattern:pattern );
  ret = chomp( ret );
  ssh_shell_close( shell );

  if( ! ret ) {
    if( debug_enabled ) {
      debug_str += 'NOTE: Failed to read response from open shell / session\n';
      if( pattern )
        debug_str += 'RES:  (empty / no response / received response doesn\'t match given pattern "' + pattern + '")';
      else
        debug_str += 'RES:  (empty / no response)';
      debug_str += '\n---------------------------------------------------------';
      display( debug_str );
    }
    return FALSE;
  }

  if( debug_enabled )
    debug_str += '\nRES (before clean up):\n--- added separator start ---\n' + ret + '\n--- added separator end   ---\n';

  # Just clear any possible return which includes our sent command from the buffer.
  # nb: While the "stty -echo" command above should already take care of this we're still keeping it
  # as an additional fallback (if e.g. the stty command isn't available / accessible for some reason).
  ret = str_replace( string:ret, find:cmd + '\n', replace:"" );

  # If pty == FALSE we don't want to have the shell prompt (which is returned / included in the
  # response to our command) returned. We have defined our own shell prompt (via export PS1 above)
  # so we can strip this line away more easily.
  if( ! pty && ret )
    ret = str_replace( string:ret, find:"##greenbone-defined-shell-prompt##", replace:"" );

  ret = chomp( ret );

  if( debug_enabled ) {
    if( ! ret )
      debug_str += '\nRES:  (empty after clean up)';
    else
      debug_str += '\nRES (after clean up):\n--- added separator start ---\n' + ret + '\n--- added separator end   ---';
    debug_str += '\n---------------------------------------------------------';
    display( debug_str );
  }

  return( ret );
}
#------------------------------------------------------------------#
# Connection re-use                                                #
#------------------------------------------------------------------#

# Returns a socket to an already established connection
#
# It seems that this function is not used at all.  The SVN shows that
# it has been here since 2005 without any change. (wk 2012-08-16).
function ssh_reuse_connection()
{
}


#
# Release the shared SSH connection so that another script can write to
# it
#
# This function is called by many scripts but obviously only for
# cleanup purposes.  Given that ssh_cmd takes a socket argument it is
# questionable how this function was supposed to work.  A global ssh
# socket is not in use. (wk 2012-08-16)
function ssh_close_connection()
{
}


# Open an ssh connection and return the socket on success.
# Authentication data needs to be passed to this function.
#
# Similar to ssh_reuse_connection and ssh_close_connection, this
# function is pretty old and has never been implemented in the way its
# name may surmise.  The function returns a socket on success but 0 on
# error - this is a bit surprising.
function ssh_login_or_reuse_connection() {

  local_var login, password, priv, passphrase, sess, auth_successful, soc;

  login      = kb_ssh_login();
  password   = kb_ssh_password();
  priv       = kb_ssh_privatekey();
  passphrase = kb_ssh_passphrase();

  if( ! login && ( ! password && ! priv ) )
    return 0;

  sess = ssh_connect();
  if( ! sess )
    return 0;

  auth_successful = ssh_userauth( sess, login:login, password:password, privatekey:priv, passphrase:passphrase );

  # nb: ssh_userauth() is returning 0 on success but everything else like -1, 1 or NULL is an error
  # or failure. In the initial implementation of this function "if(ssh_userauth())" was used below
  # to cover all != 0 cases but the NULL case was missed which is now also checked below.
  if( isnull( auth_successful ) || auth_successful ) {
    ssh_disconnect( sess );
    last_sess = 0;
    return 0;
  }

  soc = ssh_get_sock( sess );
  _last_libssh_sess = sess;
  return soc;
}

# Connect to the host HOSTNAME via TCP and setup an ssh connection.
# If SOCKET is given that socket will be used instead of a creating a
# new tcp connection.  On success an ssh session to the host has been
# established; the caller may then run an authentication.  If this
# connection is no longer needed, ssh_disconnect may be used to
# disconnect and close the socket.  On success the function returns a
# non-zero integer identifying the ssh session; zero is returned on
# error.
#
# internal function ssh_connect(socket)


# Disconnect the ssh session SESSION.  This also closes the underlying
# socket; regardless whether it was opened by ssh_connect or passed to
# it.
#
# internal function ssh_disconnect(session)


# This is a standalone version of ssh_cmd which does the same as
#    ssh host CMD
# would do on a command line.  Its implementation uses libssh.  It
# should be used only for a single command to a host because each use
# requires running the expensive ssh handshake.
function ssh_cmd_exec( cmd ) {

  local_var cmd;
  local_var login, password, priv, passphrase, sess, auth_successful, result;

  if( ! cmd ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cmd#-#ssh_cmd_exec" );
    return;
  }

  login      = kb_ssh_login();
  password   = kb_ssh_password();
  priv       = kb_ssh_privatekey();
  passphrase = kb_ssh_passphrase();

  sess = ssh_connect();
  if( ! sess )
    return NULL;

  auth_successful = ssh_userauth( sess, login:login, password:password, privatekey:priv, passphrase:passphrase );

  # nb: ssh_userauth() is returning 0 on success but everything else like -1, 1 or NULL is an error
  # or failure. In the initial implementation of this function "if(ssh_userauth())" was used below
  # to cover all != 0 cases but the NULL case was missed which is now also checked below.
  if( isnull( auth_successful ) || auth_successful ) {
    ssh_disconnect( sess );
    return NULL;
  }

  result = ssh_request_exec( sess, cmd:cmd, stdout:1, stderr:1 );
  ssh_disconnect( sess );
  return chomp( result );
}

# Workaround to get the server banner from a freshly opened socket.
# This should be replaced as soon as we can switch to libssh 0.6 which
# allows us to use ssh_get_server_banner.

# Previous comment from ssh_detect.nasl:
# The ssh_get_server_banner function will only be available after
# we switch to libssh 0.6. Thus for the time being, we use a
# workaround.

# Previous comment from gb_greenbone_os_ssh_detect.nasl:
# We do not need to login to get the banner. Until we can
# switch to libssh 0.6 we use our hacked up version.
# After the switch we may want to have a login function
# which terminates the connection right before the KEX
# protocol part. This will allows us to get the server
# banner without a need to try a login.

function ssh_hack_get_server_version( socket ) {

  local_var socket;
  local_var buf;

  if( ! socket ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ssh_hack_get_server_version" );
    return;
  }

  buf = recv_line( socket:socket, length:1024 );

  if( ! buf ) {
    ssh_set_error( msg:"The scanner did not receive server's version" );
    return 0;
  }

  if( ! ssh_verify_server_ident( data:buf ) ) {
    ssh_set_error( msg:"Remote service is not a valid SSH service" );
    return 0;
  }

  if( '\r\n' >< buf )
    buf = buf - '\r\n';
  else
    buf = buf - '\n';

  return buf;
}

function ssh_reconnect( sock ) {

  local_var sock;

  if( ! sock ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#ssh_reconnect" );
    return;
  }

  ssh_disconnect( ssh_session_id_from_sock( sock ) );
  sleep( 1 );
  sock = ssh_login_or_reuse_connection();

  if( ! sock ) return;

  return sock;

}

# @brief Returns all SSH ports of the target system which are saved
#        in the KB entry "Services/ssh" found by the scanner. If no
#        ports were found open or no "default" parameter is passed
#        (if "nodefault" isn't set to TRUE) it will exit. In the case
#        where the "unscanned_closed" scanner setting is set to "no"
#        it will return the port passed via the default parameter.
#
# @note This function will fork on multiple open ports.
#
# @param default          The port to return if "unscanned_closed" is set to "no" and no ports have been found open.
# @param nodefault        Don't exit if no "default" parameter is passed, it still will return if no SSH servers are detected at all.
# @param ignore_unscanned Returns the ports even if they were "unscanned" previously.
#
# @return The open / found SSH ports or the port passed via the default parameter in the case of no found ports
#         and "unscanned_closed" is set to "no".
#
function ssh_get_port( default, nodefault, ignore_unscanned ) {

  local_var default, nodefault, ignore_unscanned;
  local_var port;

  if( ! default && ! nodefault ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#ssh_get_port" );
    exit( 0 );
  }

  port = get_kb_item( "Services/ssh" );
  if( port )
    default = port;

  # nb: If this is the case we haven't found an open port, default wasn't passed
  # and nodefault was set to TRUE. We can't continue in this case.
  if( ! default )
    exit( 0 );

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if( port_is_marked_fragile( port:default ) )
    exit( 0 );

  if( ! get_port_state( default ) )
    exit( 0 );

  return default;
}

# @brief Returns all SSH ports of the target system which are saved in
#        the KB entry "Services/ssh" found by the scanner. If no ports
#        were found open or no list is passed to the "default_port_list"
#        parameter the function will return an empty list. In the case
#        where the "unscanned_closed" scanner setting is set to "no" it
#        will return a default set of SSH ports (namely 22) or (if
#        passed) the ports included in the list of the default_port_list
#        parameter.
#
# @note In contrast to @ref ssh_get_port this function will not fork
#       and return a list instead. This should be used e.g. for
#       Detection-VTs where we want to make sure that we're not getting
#       blocked by the remote service with to many concurrent connections.
#
# @param default_port_list The list of ports to return (overwriting the internal defaults) if "unscanned_closed"
#                          is set to "no" and no ports have been found open.
# @param ignore_unscanned  Returns the ports even if they were "unscanned" previously.
#
# @return The open / found SSH ports, if none were found an empty list. In the case of no found ports and
#         "unscanned_closed" is set to "no" a set of default ports or the list passed to the default_port_list
#         parameter.
#
function ssh_get_ports( default_port_list, ignore_unscanned ) {

  local_var default_port_list, ignore_unscanned;
  local_var final_port_list, check_port_list, default_ports, num_ports, ports, _port;

  final_port_list = make_list();
  check_port_list = make_list();
  default_ports = make_list( 22 );
  num_ports = 0;

  ports = get_kb_list( "Services/ssh" );
  if( ports && typeof( ports ) == "array" ) {
    foreach _port( ports ) {
      num_ports++;
      check_port_list = make_list( check_port_list, _port );
    }
  }

  if( num_ports == 0 ) {
    if( default_port_list && typeof( default_port_list ) == "array" )
      check_port_list = default_port_list;
    else
      check_port_list = default_ports;
  }

  foreach _port( check_port_list ) {

    if( ! ignore_unscanned && ! get_port_state( _port ) )
      continue;

    # Includes e.g. PJL ports which are printing everything
    # sent to them so don't include them here.
    if( port_is_marked_fragile( port:_port ) )
      continue;

    final_port_list = make_list( final_port_list, _port );
  }
  return final_port_list;
}

# @brief Checks if any random user/pass pair is accepted by the SSH service. The function
#        will save the status (broken/not broken) and if the status was already checked
#        within the KB to avoid that the same check is conducted multiple times.
#
# @param port The TCP port of the remote SSH service to check.
#
# @return TRUE if any random username/password pair is accepted by the SSH service, FALSE
#         otherwise and NULL if it was not possible to get a connection to the service or if
#         no port parameter was passed.
#
function ssh_broken_random_login( port ) {

  local_var port;
  local_var login_banner, banner, count, logins, i, user, pass, soc, login;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ssh_broken_random_login" );
    return NULL;
  }

  if( get_kb_item( "SSH/" + port + "/broken/random_login" ) )
    return TRUE;

  if( get_kb_item( "SSH/" + port + "/broken/random_login/checked" ) )
    return FALSE;

  login_banner = ssh_get_login_banner( port:port );
  banner = ssh_get_serverbanner( port:port );
  count  = 0;
  logins = 0;

  for( i = 1; i < 3; i++ ) {

    # nb: See gb_ssh_os_detection.nasl
    if( i == 1 && ( banner =~ "(cisco|FIPS User Access Verification)" || "Cisco Systems, Inc. All rights Reserved" >< login_banner ) ) {
      user = "Anonymous";
      pass = "";
    } else {
      user = rand_str( length:7 + i, charset:"abcdefghiklmnopqrstuvwxyz" );
      pass = rand_str( length:7 + i, charset:"ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz" );
    }

    if( ! soc = open_sock_tcp( port ) ) {
      sleep( 1 );
      continue;
    }

    count++;
    login = ssh_login( socket:soc, login:user, password:pass, priv:NULL, passphrase:NULL );
    close( soc );
    if( login == 0 )
      logins++;

    sleep( 1 );
  }

  if( count > 0 )
    set_kb_item( name:"SSH/" + port + "/broken/random_login/checked", value:TRUE );

  if( logins > 0 ) {
    set_kb_item( name:"SSH/" + port + "/broken/random_login", value:TRUE );
    return TRUE;
  }

  if( count == 0 )
    return NULL;
  else
    return FALSE;
}

# @brief Tries to find the given binary name (e.g. "bash") via an SSH login on the target
#        system by using the linux tools "locate", "whereis" and "which".
#
# @param prog_name The (mandatory) binary to search for (e.g. "bash").
# @param sock      The (optional) SSH socket of the remote SSH service.
#
# @return An list of binaries found or NULL if the target is not a Linux/Unix System,
#         no connection could be opened to the target or the mandatory function
#         parameter "prog_name" wasn't passed.
#
function ssh_find_bin( prog_name, sock ) {

  local_var prog_name, sock;
  local_var cl, r, where, _r, final_list, which;

  if( get_kb_item( "ssh/no_linux_shell" ) )
    return NULL;

  if( ! prog_name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#prog_name#-#ssh_find_bin" );
    return NULL;
  }

  if( ! sock )
    sock = ssh_login_or_reuse_connection();

  if( ! sock )
    return NULL;

  cl = ssh_check_locate( sock:sock );

  if( cl )
    r = split( ssh_cmd( socket:sock, cmd:"locate -ei *bin/" + prog_name, timeout:60 ) );
  else
    r = NULL;

  # Binary found:
  # /bin/bash
  #
  # Binary not found:
  # <empty response>
  if( ! r || "bin/" + prog_name >!< r ) {

    where = ssh_cmd( socket:sock, cmd:"whereis -b " + prog_name, timeout:60 );

    # Binary found:
    # bash: /bin/bash /etc/bash.bashrc
    #
    # Binary not found:
    # foo:
    #
    # Notes:
    # - Sometimes whereis (at least on Debian 9) also returned a directory
    # (this contains the mupdf-x11 binary) which is quite unexpected...
    # mupdf: /usr/bin/mupdf /usr/lib/mupdf
    # - As shown in the first example whereis is also returning
    # /etc/bash.bashrc which we want to exclude here.
    # Both cases are covered by the additional check / final_list handling below.
    if( prog_name + ":" >< where && "bin/" + prog_name >< where ) {
      r = split( substr( where - ( prog_name + ":" ), 1 ), sep:" " );
      final_list = make_list();
      foreach _r( r ) {
        if( "bin/" + prog_name >< _r )
          final_list = make_list( final_list, _r );
      }
      if( max_index( final_list ) > 0 )
        r = final_list;
      else
        r = NULL;
    } else {
      r = NULL;
    }
  }

  if( ! r ) {

    which = ssh_cmd( socket:sock, cmd:"which -a " + prog_name, timeout:60 );

    # Binary not found has either an empty response or something like e.g.
    # the following depending on the used which version / variant:
    # which: no bash found in (/bin:/usr/bin:/usr/local/bin)
    if( ! which || "bin/" >!< which || "which: no " + prog_name >< which )
      return NULL;

    # Binary found:
    # /bin/bash
    if( eregmatch( string:which, pattern:'^/.*bin/' + prog_name, icase:FALSE ) )
      r = split( which );
    else
      return NULL;
  }

  return( r );
}

# @brief Searches for a file on the target SSH server
#
# @param file_name                    The filename to search for (e.g. ssh, sshd, ...). Start with a
#                                     "/" to exclude filenames like (.*)ssh (e.g. server-ssh).
#                                     Note: The search is done case sensitive.
# @param useregex                     If set to TRUE specifies if a regexp search in the locate
#                                     (-r/--regexp) call is used. For the find search a -regex is
#                                     passed / used if set to TRUE.
# @param sock                         The socket for the connection to the remote SSH service.
# @param follow_symlinks              If set to TRUE symbolic links are being followed when using "find"
# @param remove_search_exclude_string An (optional) string to remove from the "search_exclude_paths" setting
#
# @example Example call to search for all (ssh and sshd) files:
#          file_name:"/sshd?$"
#          useregex:TRUE
#
#          The "?" makes the ending "d" optional and so all "ssh" and "sshd" files are returned.
#
# @example Example call to search for three different files in one call with an regex call:
#          file_name:"/salt-(master|api|minion)$"
#          useregex:TRUE
#
# @return A list containing the found files or NULL if none were found or the function was started against a non-linux system.

function ssh_find_file( file_name, useregex, sock, follow_symlinks, remove_search_exclude_string ) {

  local_var file_name, useregex, sock, follow_symlinks, remove_search_exclude_string;
  local_var res, lparam, lparam_no_e, use_find, descend_directories, search_exclude_paths, cl, _res, tmp_list;
  local_var final_list, _item, maxdepth, cmd, check_pattern, start, end, current_timeout;

  if( get_kb_item( "ssh/no_linux_shell" ) )
    return;

  if( ! file_name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file_name#-#ssh_find_file" );
    return;
  }

  res = NULL;

  # nb: "plocate" on Debian 11.x and below doesn't support the -e parameter so we need to use a
  # different one later depending on the response.
  if( useregex ) {
    lparam = "-ei --regex";
    lparam_no_e = "-i --regex";
  } else {
    lparam = "-ei";
    lparam_no_e = "-i";
  }

  use_find = get_kb_item( "ssh/lsc/enable_find" );
  descend_directories = get_kb_item( "ssh/lsc/descend_ofs" );

  if( isnull( use_find ) )
    use_find = "yes";

  if( isnull( descend_directories ) )
    descend_directories = "yes";

  if( ! search_exclude_paths = get_kb_item( "ssh/lsc/search_exclude_paths" ) ) {
    # nb:
    # - /run is excluded because it is a new storage of transient state files on at least Debian.
    #   See https://wiki.debian.org/ReleaseGoals/RunDirectory for more info
    # - /lost+found can be placed on any partition and is created by "fsck" during recovery of
    #   corrupted files. Including this folder by default doesn't make any sense as it could include
    #   a huge amount of binary data. See the following for more background info:
    #   https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/lostfound.html
    # - The "/lost\+found" is used separately to catch e.g. these:
    #   /var/lib/lost+found
    #   /var/lost+found
    #   /lost+found
    #   but NOT this:
    #   /usr/sbin/mklost+found
    # - See e.g. https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/var.html for more background
    #   info on each excluded dir in "/var". For example "/var/opt" is excluded because it is only
    #   used for "Variable data" of the packages installed to "/opt" (nb: This one shouldn't be
    #   excluded) according to:
    #   https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch05s12.html
    # - "/proc" is "very special in that it is also a virtual filesystem" and "It doesn't contain
    #   'real' files".
    #   - See e.g. https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/proc.html
    #   - The folder will be also always excluded in "ssh_find_file()" of "ssh_func.inc" when using
    #     "find" and if the exclude path is configured to 'None'
    # - Keep in sync with the default pattern in ssh_func.inc. This string is used at multiple
    #   places so that VTs calling the function from command line (via openvas-nasl) will get the
    #   same default regex
    search_exclude_paths = "^(/(proc|afs|dev|media|mnt|net|run|sfs|sys|tmp|udev|var/(backups|cache|lib|local|lock|log|mail|opt|run|spool|tmp)|etc/init\.d|usr/share/doc)|.*/lost\+found)";
  }

  if( remove_search_exclude_string )
    search_exclude_paths = str_replace( string:search_exclude_paths, find:remove_search_exclude_string, replace:"" );

  if( ! sock )
    sock = ssh_login_or_reuse_connection();

  if( ! sock )
    return NULL;

  cl = ssh_check_locate( sock:sock );
  if( cl ) {
    res = ssh_cmd( socket:sock, cmd:"locate " + lparam + ' "' + file_name + '"', timeout:60 );
    if( res && "locate: invalid option -- 'e'" >< res )
      res = ssh_cmd( socket:sock, cmd:"locate " + lparam_no_e + ' "' + file_name + '"', timeout:60 );

    res = chomp( res );

    # nb: Just an additional basic response check but ssh_check_locate() should have been covered
    # most weird response cases for non-linux SSH systems.
    if( res && res[0] == "/" ) {

      _res = split( res );
      tmp_list = make_list();
      final_list = make_list();
      foreach _item( _res ) {

        # nb: Just to make sure that no trailing newlines are included in the list so that VTs
        # calling this functions don't need to care about it.
        _item = chomp( _item );
        if( ! _item )
          continue;

        # nb: We only want to call egrep() if useregex is set to TRUE so that we don't need to
        # handle escaping of e.g. a dot in the string passed to file_name if useregex is set to FALSE.
        if( useregex ) {
          if( egrep( string:_item, pattern:file_name, icase:FALSE ) )
            tmp_list = make_list( tmp_list, _item );
        } else {
          if( file_name >< _item )
            tmp_list = make_list( tmp_list, _item );
        }
      }

      if( search_exclude_paths && search_exclude_paths != "None" ) {

        # And now just go over the tmp_list() to throw out all items which should be excluded
        foreach _item( tmp_list ) {
          if( ! egrep( string:_item, pattern:search_exclude_paths, icase:TRUE ) )
            final_list = make_list( final_list, _item );
        }
      } else {
        final_list = tmp_list;
      }

      if( max_index( final_list ) > 0 )
        res = final_list;
      else
        res = NULL;
   }
    else
      res = NULL;
  }

  if( ! res && "yes" >< use_find ) {
    cmd = 'find "/"';

    if( "no" >< descend_directories )
      cmd += " -xdev";

    if( ! maxdepth = get_kb_item( "ssh/lsc/find_maxdepth" ) )
      maxdepth = "12";

    if( maxdepth == "zero" ) # nb: Special case from lsc_options.nasl as the KB can't hold a "0" in the KB.
      maxdepth = "0";

    # nb: check_pattern is used to check if some special devices are wrongly echoing back our command
    # which could cause false detections with number based regex calls.
    check_pattern = " -maxdepth " + maxdepth + " -mindepth 1";
    cmd += check_pattern;

    # nb: We always want to have this type of regex available / activated.
    cmd += " -regextype posix-extended";

    if( search_exclude_paths && search_exclude_paths != "None" )
      cmd += ' -regex "' + search_exclude_paths  + '" -prune -o';
    # nb: "/proc" should be always excluded even if 'None' passed. This is also described in the
    # metadata of lsc_options.nasl.
    else
      cmd += ' -path "*/proc" -prune -o';

    # nb: Depending on the chosen option we need to prepend different prefixes to the cmd because
    # find handles the search differently in both cases (see "man find" for more info).
    if( useregex )
      cmd += ' -regex ".*';
    else
      cmd += ' -path "*';
    cmd += file_name + '"';
    cmd += " -a -type f";
    if( follow_symlinks )
      cmd += ",l";
    cmd += " -print 2>/dev/null";

    start = unixtime();
    res = ssh_cmd( socket:sock, cmd:cmd, timeout:60 );
    end = unixtime();
    res = chomp( res );

    if( res && res[0] == "/" && check_pattern >!< res ) {

      _res = split( res );
      final_list = make_list();
      foreach _item( _res ) {

        # nb: Just to make sure that no trailing newlines are included in the list so that VTs
        # calling this functions don't need to care about it.
        _item = chomp( _item );
        if( ! _item )
          continue;

        # nb: We only want to call egrep() if useregex is set to TRUE so that we don't need to
        # handle escaping of e.g. a dot in the string passed to file_name if useregex is set to FALSE.
        if( useregex ) {
          if( egrep( string:_item, pattern:file_name, icase:FALSE ) )
            final_list = make_list( final_list, _item );
        } else {
          if( file_name >< _item )
            final_list = make_list( final_list, _item );
        }
      }

      if( max_index( final_list ) > 0 )
        res = final_list;
      else
        res = NULL;

    } else {
      res = NULL;
    }

    # A local find should take only a few seconds. If we're reaching more then this we can try to
    # add the -xdev parameter to find to bring down the time if a network based file filesystem
    # like NFS or AFS is mounted at the target host. To be safe we're counting the timeouts and
    # only add the -xdev once we have reached the timeout three times.
    current_timeout = get_kb_item( "ssh/lsc/find_timeout" );
    # nb: GVM-9 and below versions (which are EOL) had a timeout of 15 seconds, all current and
    # supported versions have 30 seconds so this higher timeout is used here.
    if( end - start > 29 ) {
      current_timeout++;
      replace_kb_item( name:"ssh/lsc/find_timeout", value:current_timeout );
    }
    if( "yes" >< descend_directories && current_timeout >= 3 ) {
      replace_kb_item( name:"ssh/lsc/descend_ofs", value:"no" );
    }
  }

  if( ! res )
    return NULL;

  return res;
}

function ssh_get_bin_version( full_prog_name, version_argv, ver_pattern, sock ) {

  local_var full_prog_name, version_argv, ver_pattern, sock;
  local_var r, loc_version;

  if( get_kb_item( "ssh/no_linux_shell" ) )
    return;

  if( ! full_prog_name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#full_prog_name#-#ssh_get_bin_version" );
    return;
  }

  # nb: "isnull()" and not "!" is used here to allow an empty string passed
  if( isnull( version_argv ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version_argv#-#ssh_get_bin_version" );

  if( ! ver_pattern ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ver_pattern#-#ssh_get_bin_version" );

  full_prog_name = chomp( full_prog_name );
  version_argv = chomp( version_argv );

  if( ! sock)
    sock = ssh_login_or_reuse_connection();

  if( sock ) {
    if( strlen( version_argv ) > 0 )
      r = ssh_cmd( socket:sock, cmd:full_prog_name + " " + version_argv, timeout:60 );
    else
      r = ssh_cmd( socket:sock, cmd:full_prog_name, timeout:60 );

    r = chomp( r );
  }

  if( ! r )
    return;

  loc_version = eregmatch( pattern:ver_pattern, string:r );
  if( loc_version != NULL )
    loc_version[max_index( loc_version )] = r;

  return( loc_version );
}

# @brief Checks if the "locate" command is available on the remote SSH service.
#        Additionally save the reason (namely the result of the SSH command)
#        why the locate isn't available within the KB key ssh/locate/broken.
#
# @param sock the SSH socket of the connection to the remote SSH service.
#
# @return TRUE if the locate command is available, FALSE otherwise and NULL
#              if no sock parameter was passed.
#
function ssh_check_locate( sock ) {

  local_var sock;
  local_var r;

  if( ! sock ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#sock#-#ssh_check_locate" );
    return;
  }

  if( get_kb_item( "ssh/locate/available" ) )
    return TRUE;

  if( get_kb_item( "ssh/no_linux_shell" ) )
    return FALSE;

  if( get_kb_item( "ssh/locate/broken" ) )
    return FALSE;

  r = ssh_cmd( socket:sock, cmd:"locate -S", timeout:60, return_errors:TRUE, return_linux_errors_only:TRUE );

  # nb: slocate, plocate (and maybe other variants?) don't have the database statistic (-S) command.
  # Just try a search instead, if the database isn't build it will return something like e.g.:
  # warning: locate: could not open database: /path/to/db: No such file or directory or
  # locate: fatal error: Could not find user database '/path/to/db':  No such file or directory
  # /var/lib/plocate/plocate.db: No such file or directory
  if( "locate: invalid option -- S" >< r ||
      "locate: unknown option -- S" >< r ||
      "locate: invalid option -- 'S'" >< r # plocate (on Debian), will be used on Debian bookwork if "mlocate" was installed previously
    ) {
    r = ssh_cmd( socket:sock, cmd:"locate /bin/bash", timeout:60 ); # nb: Assuming that /bin/bash exists on the target system
    if( "locate:" >!< r && "/bin/bash" >< r ) {
      set_kb_item( name:"ssh/locate/available", value:TRUE );
      return TRUE;
    } else if( "locate:" >!< r ) {
      r = ssh_cmd( socket:sock, cmd:"locate /bin/sh", timeout:60 ); # nb: Another try for /bin/sh if /bin/bash doesn't exists
      if( "locate:" >!< r && "/bin/sh" >< r ) {
        set_kb_item( name:"ssh/locate/available", value:TRUE );
        return TRUE;
      }
    }
  }

  if( ( "Database /" >!< r ||
      ( "bytes" >!< r &&
        "Compression" >!< r &&
        "Filenames"   >!< r &&
        "file names"  >!< r ) ) ||
        "command not found" >< tolower( r ) ||
        "locate: not found" >< r ||
        "locate:" >< r ) { # nb: Also includes an outdated database like "locate: warning: database /var/cache/locate/locatedb is more than 8 days old (actual age is 9,3 days)"

    if( ! r )
      r = "No response received from the remote SSH service.";

    set_kb_item( name:"ssh/locate/broken", value:r );
    return FALSE;
  }
  set_kb_item( name:"ssh/locate/available", value:TRUE );
  return TRUE;
}

function ssh_get_serverbanner( port ) {

  local_var port;
  local_var banner, soc;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ssh_get_serverbanner" );
    return;
  }

  if( ! get_port_state( port ) )
    return;

  banner = get_kb_item( "SSH/server_banner/" + port );
  if( banner )
    return banner;

  soc = open_sock_tcp( port );
  if( ! soc )
    return;

  banner = ssh_hack_get_server_version( socket:soc );
  close( soc );

  if( banner )
    replace_kb_item( name:"SSH/server_banner/" + port, value:banner );

  return banner;
}

# @brief Cleans a passed string from various known messages returned
#        by @ref ssh_cmd which might interfere with various detection
#        pattern relying on a string without those messages.
#
# @param data the string to clean
#
# @return the cleaned string
#
function ssh_clean_cmd_from_err( data ) {

  local_var data;

  if( ! data )
    return data;

  # uname: Could not chdir to home directory /home/test: No such file or directory
  # Could not chdir to home directory /home/test: No such file or directory
  # Could not chdir to home directory /home/test: Permission denied
  #
  # Those messages itself might show up if a user for the SSH connection is used without e.g. a
  # home directory on the target host.
  #
  # nb: Keep the pattern in single quotes...
  data = ereg_replace( string:data, pattern:'^([a-zA-Z]+: )?Could not chdir to home directory [^:]+: (No such file or directory|Permission denied)[\r\n]*', replace:"" );

  # Returned on Mac OS X if the subversion binary is called with the --version parameter.
  # It is unknown why some systems behaving like this and which other applications/binaries are affected.
  #
  # xcode-select: error: no developer tools were found at '/Applications/Xcode.app', and no install could be requested (perhaps no UI is present), please install manually from 'developer.apple.com'.
  #
  # nb: Keep the pattern in single quotes...
  data = ereg_replace( string:data, pattern:'^xcode-select: error: no developer tools were found at \'/Applications/Xcode\\.app\', and no install could be requested \\(perhaps no UI is present\\), please install manually from \'developer\\.apple\\.com\'\\.[\r\n]*', replace:"" );

  return data;
}

# @brief looks on linux host via SSH if a given file can be found.
#
# @param sock an open SSH socket (optional). If non given, a new one will be opened.
# @param file the file to check the existence(filepath)
#
# @return TRUE if the file can be found, FALSE otherwise and NULL if not all
#         required parameters are passed or no connection could be opened to the target.
#
function ssh_check_file_existence( sock, file ) {

  local_var sock, file;
  local_var cmd, file_exists;

  if( ! sock ) {
    sock = ssh_login_or_reuse_connection();
  }

  if( ! file ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#ssh_check_file_existence" );
    return;
  }

  cmd = '[ -f ' + file + ' ] && echo "TRUE" || echo "FALSE"';
  file_exists = ssh_cmd( cmd:cmd, socket:sock );

  if( file_exists == 'TRUE' )
    return TRUE;
  else if( file_exists == 'FALSE' )
    return FALSE;
  else
    return;
}

# @brief looks on linux host via SSH if a given file can be read.
#
# @param sock an open SSH socket (optional). If non given, a new one will be opened.
# @param file the file to check if it can be read(filepath)
#
# @return TRUE if the file can be read, FALSE otherwise and NULL if not all
#         required parameters are passed or no connection could be opened to the target.
#
function ssh_check_file_readable( sock, file ) {

  local_var sock, file;
  local_var cmd, file_readable;

  if( ! sock )
    sock = ssh_login_or_reuse_connection();

  if( ! file ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#ssh_check_file_existence" );
    return;
  }

  cmd = '[ -r ' + file + ' ] && echo "TRUE" || echo "FALSE"';
  file_readable = ssh_cmd( cmd:cmd, socket:sock );

  if( file_readable == 'TRUE' )
    return TRUE;
  else if( file_readable == 'FALSE' )
    return FALSE;
  else
    return;
}

# @brief Gets the SSH login banner shown when a log in is done into the remote SSH service.
#
# @param port          The TCP port of the remote SSH service to check (mandatory).
# @param sock          The socket for the connection to the remote SSH service (optional).
#                      If given the function will re-use this socket instead of opening a
#                      new socket / connection to the remote SSH service.
# @param login         The (optional) login to be used for the connection to the SSH service.
#                      Defaults to the return value of @ref get_vt_strings if not given.
# @param passwd        The (optional) password to be used for the connection to the SSH service.
#                      Defaults to the return value of @ref get_vt_strings if not given.
# @param privkey       The (optional) SSH private key to be used for the connection to the
#                      SSH service.
#                      If none given a password like described above is used.
# @param keypassphrase The (optional) passphrase of the given SSH private key to be used for the
#                      connection to the SSH service.
#
# @note The SSH login banner is the banner which is e.g. configured in OpenSSH with
#       the "Banner" configuration of the "sshd_config" config file.
#
# @note The function is not closing the passed socket (via the "sock" parameter). This is
#       done to provide the possibility to gather / query additional information from the
#       remote SSH service via the same session without doing another login / connection.
#
# @return The SSH login banner if provided by the remote SSH service, FALSE otherwise
#         and NULL if not all required parameters are passed or no connection could be
#         opened to the target.
#
function ssh_get_login_banner( port, sock, login, passwd, privkey, keypassphrase ) {

  # nb: The "old" get_ssh_banner() function had the following comment:
  # ---
  # Please use ssh_get_session_banner directly for new code.
  # The saved session id is just a bad hack.
  # ---
  # It is currently unclear what this means. Additionally the text probably
  # was referring to "ssh_get_issue_banner".

  local_var port, sock, login, passwd, privkey, keypassphrase;
  local_var banner, nosock, vt_strings, sess_id;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ssh_get_login_banner" );
    return;
  }

  banner = get_kb_item( "SSH/login_banner/" + port );
  if( banner ) {

    # nb: Used to avoid another connection to the service if there is no login banner
    # available at all. We can't use "0" or "FALSE" for a KB entry (see note below).
    if( banner != "None Available" )
      return banner;
    else
      return FALSE;
  }

  if( ! sock ) {

    if( ! get_port_state( port ) )
      return;

    sock = open_sock_tcp( port );
    if( ! sock )
      return;

    nosock = TRUE;
  }

  if( ! login || ! passwd ) {

    vt_strings = get_vt_strings();

    if( ! login )
      login = vt_strings["default"];

    if( ! passwd && ! privkey )
      passwd = vt_strings["default"];
  }

  ssh_login( socket:sock, login:login, password:passwd,
             priv:privkey, passphrase:keypassphrase );

  sess_id = ssh_session_id_from_sock( sock );
  if( sess_id )
    _last_libssh_sess = sess_id;

  banner = ssh_get_issue_banner( _last_libssh_sess );

  # close socket only if it was opened by this function
  if( nosock )
    close( sock );

  banner = chomp( banner );
  if( strlen( banner ) > 0 ) {
    set_kb_item( name:"SSH/login_banner/" + port, value:banner );
    return banner;
  } else {
    set_kb_item( name:"SSH/login_banner/" + port, value:"None Available" ); # nb: We can't add 0 or FALSE here...
    return FALSE;
  }
}

# @brief Verify if the received/passed data is a valid SSH server ident string.
#
# @param data The data to be verified.
#
# @return TRUE if the passed data is a valid SSH server ident string, FALSE otherwise.
#
function ssh_verify_server_ident( data ) {

  local_var data;

  data = chomp( data );
  if( ! data )
    return FALSE;

  # e.g.
  # SSH-%d.%d-servername
  # or (special case):
  # SSH-2.0--
  if( ereg( string:data, pattern:"^SSH-*[0-9]\.*[0-9]-*[^\n]", icase:FALSE ) )
    return TRUE;

  return FALSE;
}

# @brief Returns the info if an SSH login should be tried / done against the target.
#
# @param port The TCP port of the remote SSH service.
#
# @return TRUE if a login shouldn't be tried, FALSE otherwise.
#
function ssh_dont_try_login( port ) {

  local_var port;
  local_var banner;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ssh_dont_try_login" );
    return NULL;
  }

  banner = ssh_get_serverbanner( port:port );

  # Teamspeak 3 Server up to the recent 3.13.7 is running a specific variant of libssh which e.g.:
  # - doesn't allow any login
  # - ssh_detect.nasl doesn't detect this as SSH
  # - a special request in find_service6.nasl is required for the detection
  # - default_ssh_credentials.nasl and other SSH login based VTs are running into timeouts
  # For now we're excluding the libssh server from any active login VTs to avoid timeouts and
  # unnecessary overlong scan times.
  if( banner && banner =~ "^SSH-2\.0-libssh" &&
      get_kb_item( "teamspeak3_server/detected" ) )
    return TRUE;

  return FALSE;
}
