# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


# NB: So far done to keep coding style similar to SMB-implementation
#     The amount of overhead nowadays probably is negligible and
#     prob. is acceptable with the benefit of not having to add
#     this file as include to resp. nasl scripts.

global_var __winrm_failure, __winrm_success, __winrm_krb_success, __winrm_ntlm_success;

# nb: global connection / credential options are *assumed correct* by design for the rest
#     of the code and reflect the resp. WinRM/{explicit_non_default_argument}
#     This is either because they were hardcoded by the user via the GUI
#     or, because they were successfully used when running with some default option.
global_var __winrm_path, __winrm_port, __winrm_ssl;
global_var __winrm_domain, __winrm_username, __winrm_password;
global_var __winrm_disable_KRB_to_NTLM_fallback;
global_var __winrm_ports_enabled, __winrm_port_set, __winrm_ssl_set, __winrm_smb_ports_enabled, __winrm_can_run, __winrm_hostname_permanently_null;
global_var __winrm_result_double_check;


global_var __winrm_local_nonrecoverable_failure;

global_var ssl_cnt;

global_var __winrm_krb_prepared;

# TODO: __winrm_debug_kbs and respective logging should be removable once we consider
#       it ready for release
global_var __winrm_debug, __winrm_debug_kbs;

global_var __winrm_internal_error_tracing;

global_var __winrm_reason_log, __winrm_fallback_log;
__winrm_reason_log = "";
__winrm_fallback_log = "";
# TODO: ensure set to FALSE for release
__winrm_debug = FALSE;
__winrm_debug_kbs = FALSE;
__winrm_internal_error_tracing = FALSE;


# Make linter happy
__winrm_host = NULL;
__winrm_kdc = NULL;
__winrm_login = NULL;
__winrm_smb_ports_enabled = NULL;
__winrm_local_nonrecoverable_failure = NULL;
__winrm_hostname_permanently_null = NULL;
__winrm_result_double_check = NULL;


# @brief    Execute the command as PS command over WinRM
#
# @returns  raw PS output; NULL in case of any error
#
function winrm_powershell_prompt( cmd ) {
  local_var cmd;
  return winrm_exec( cmd:cmd, use_CMD:FALSE );
}


# @brief    Execute the command as CMD command over WinRM
#
# @returns  raw CMD output; NULL in case of any error
#
function winrm_cmd_prompt( cmd ) {
  local_var cmd;
  return winrm_exec( cmd:cmd, use_CMD:TRUE );
}


# @brief  Executes the given command via CMD or PS over WinRM
#
# @note   A NULL result may caused by bad inputs, credentials, server-side
#         interpreter errors, library errors etc.
#         These are logged internally at runtime to the best degree possible for
#         reporting.
#
# @return Raw result of CLI. NULL on any form of error
#
function winrm_exec( cmd, use_CMD ) {
  local_var cmd, use_CMD, result;
  result = _winrm_exec( cmd:cmd, use_CMD:use_CMD, in_fallback:FALSE );
  if ( isnull( result ) )
    return;

  result = chomp( result );
  if ( ! result )
    return;

  return result;
}


# @brief  Executes the given command via CMD or PS over WinRM
#
# @return Raw result of CLI. NULL on any form of error
#
function _winrm_exec( cmd, use_CMD, in_fallback ) {
  local_var cmd, use_CMD, in_fallback;
  local_var result, infos;

  if ( ! defined_func( "psrp_cli" ) ) {
    set_kb_item( name:"login/WinRM/failure", value:TRUE );
    set_kb_item( name:"login/WinRM/failure/reason", value:"WinRM CLI is not installed" );
    set_kb_item( name:"login/WinRM/failure/kind", value:"Outdated scanner version" );
    return;
  }

  if ( ! cmd ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cmd#-#winrm_exec" );
    __winrm_local_nonrecoverable_failure = TRUE;
    return;
  }

  if ( isnull( use_CMD ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#use_CMD#-#winrm_exec" );
    use_CMD = FALSE;
  }

  if ( ! infos = kb_winrm_connectinfo() ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#infos#-#winrm_exec" );
    set_kb_item( name:"login/WinRM/failure", value:TRUE );
    set_kb_item( name:"login/WinRM/failure/reason", value:"Insufficient host info: Insufficient credentials, host could not be resolved to an IP, or the WinRM login VT was not executed." );
    return;
  }

  if ( kb_winrm_failure() )
    return;

  # overall success key should only ever be set to TRUE, nothinng else
  if ( ! kb_winrm_success() ) {
    # nb: given credential type may not equal what they are used for (no KDC entry may still
    #     result in using them for NTLM as fallback)
    if ( isnull( kb_winrm_krb_success() ) && infos["kdc"] ) {
      result = _pypsrp_cli_wrapper( cmd:cmd, use_CMD:use_CMD, infos:infos, auth:"kerberos" );

      result = check_result_and_exec_fallback_if_necessary( result:result, auth_proto:"kerberos", cmd:cmd, use_CMD:use_CMD, infos:infos );

      # nb: check on final result only
      if ( ! in_fallback ) {
        if ( result ) {
          set_kb_item( name:"login/WinRM/Kerberos/success", value:TRUE );
          set_kb_item( name:"login/WinRM/success", value:TRUE );
          __winrm_krb_success = TRUE;
          __winrm_success = TRUE;
        } else {
          set_kb_item( name:"login/WinRM/Kerberos/success", value:FALSE );
          __winrm_krb_success = FALSE;

          if ( get_kb_item( "WinRM/disable_krb_to_ntlm_fallback" ) ) {
            set_kb_item( name:"login/WinRM/failure", value:TRUE );
            __winrm_failure = TRUE;
            return;
          }
        }
      }
    } else if ( isnull( kb_winrm_ntlm_success() ) &&
                ! ( kb_winrm_disable_krb_to_ntlm_fallback() &&
                    get_kb_item( "WinRM/credential_type" == "Kerberos" ) ) ) {
      result = _pypsrp_cli_wrapper( cmd:cmd, use_CMD:use_CMD, infos:infos, auth:"ntlm" );
      # Don't fail here yet, because might be a fallback available
      result = check_result_and_exec_fallback_if_necessary( result:result, auth_proto:"NTLM", cmd:cmd, use_CMD:use_CMD, infos:infos );

      # nb: check on final result only
      if ( ! in_fallback ) {
        if ( result ) {
          set_kb_item( name:"login/WinRM/NTLM/success", value:TRUE );
          set_kb_item( name:"login/WinRM/success", value:TRUE );
          __winrm_ntlm_success = TRUE;
          __winrm_success = TRUE;
        } else {
          set_kb_item( name:"login/WinRM/NTLM/success", value:FALSE );
          set_kb_item( name:"login/WinRM/failure", value:TRUE );
          __winrm_ntlm_success = FALSE;
          __winrm_failure = TRUE;
        }
      }
    }
  } else {
    # some initial login was successful.
    # If it was successful with NTLM in the above section, NTLM was and remains allowed with the given credential and connection context.
    if ( kb_winrm_krb_success() ) {
      result = _pypsrp_cli_wrapper( cmd:cmd, use_CMD:use_CMD, infos:infos, auth:"kerberos" );
    } else {
      result = _pypsrp_cli_wrapper( cmd:cmd, use_CMD:use_CMD, infos:infos, auth:"ntlm" );
    }
    # nb: if the result is null now, something broke in between the first successful
    #     request and this one, or the command is bad (e.g., because of non-existent file path).
    result = check_result_and_exec_fallback_if_necessary( result:result, cmd:cmd, use_CMD:use_CMD, infos:infos );
  }

  return result;
}


# @brief  Wrapper around calling the Pypsrp-CLI function for easier usage on the NASL-side
#
# @return The CLIs result, as long as a valid authentication mechanism was chosen, otherwise
#         NULL
#
function _pypsrp_cli_wrapper( cmd, use_CMD, infos, auth ) {
  local_var cmd, use_CMD, infos, auth;
  local_var interpreter, result, additional_args, ssl;

  local_var data;

  if ( use_CMD ) {
    interpreter = "CMD";
  } else {
    interpreter = "PS";
  }

  if ( __winrm_debug )
    log_message( data:"Raw command to execute: '" + cmd + "' via interpreter: " + interpreter + " for OID: " + get_script_oid());

  ssl = infos["SSL"] == "yes";

  if ( auth == "ntlm" ) {
    result = psrp_cli( interpreter: interpreter, cmd:cmd,
                       host:infos["hostname"], port:infos["port"], path:infos["path"],
                       ssl:ssl,
                       authentication:"NTLM", username:infos["login"],
                       password:infos["password"]);
    data = "Wrapper content: Auth: " + auth + '\ninfos:' + infos + '\ninterpreter:' + interpreter;
  } else if ( auth == "kerberos" ) {
    # nb: so far, realm & KDC have not been needed by the CLI, if the TGT is already
    #     in the cache for our testlab, which is done by the kerberos setup calls.
    # nb: realm is *necessary* due to Scanner writing a tmp Krb conf file without
    #     default realm
    additional_args = make_list("--realm", infos["domain"]);

    # nb: Scanner removes the temp krb conf & credentials after every .nasl script.
    prepare_kerberos();

    result = psrp_cli( interpreter:interpreter, cmd:cmd,
                       host:infos["hostname"], port:infos["port"], path:infos["path"],
                       ssl:ssl,
                       authentication:"Kerberos", username:infos["login"],
                       password:infos["password"],
                       additional_args:additional_args);
  } else {
    if ( get_kb_item( "WinRM/debug_enabled" ) )
      error_message( data:"Invalid Authentication mechanism for WinRM: '" + auth + "'", port:0 );

    set_kb_item( name:"login/WinRM/failure", value:TRUE );
    set_kb_item( name:"login/WinRM/failure/kind", value:"Invalid Authentication mechanism '" + auth + "'" );
    return;
  }
  return result;
}


# @brief  Disables forced SSL usage for WinRM library if not explicitly
#         mandated in the login settings.
#
# @return TRUE if a change to the connection setup was made, otherwise FALSE
#
function disable_ssl_if_fallback_is_possible() {
  # default is: HTTPS > HTTP
  # port 5986 > 5985
  # First, try the other port, then try without HTTPS, if allowed by the admin.
  # only use other port and other SSL mechanism, if it wasn't explicitly set by the user.

  if ( ! isnull( __winrm_ssl ) ) {
    return FALSE;
  }

  # nb: https_only should force __winrm_ssl to already be set, but better by save on this one.
  if ( get_kb_item( "WinRM/default_ssl" ) == "yes" && ! get_kb_item( "WinRM/https_only" ) ) {
    replace_kb_item( name:"WinRM/default_ssl", value:"no" );
    __winrm_fallback_log += 'Applying HTTP instead of HTTPS as fallback.\n';
    return TRUE;
  }
  return FALSE;
}


# @brief  Choose default non-HTTPS port, if such a fallback can be made.
#
# @return TRUE iff a change to the connection info was made.
#
function adjust_port_if_fallback_is_possible() {
  # port 5986 > 5985, due to HTTPS > HTTP
  # First, try the other port, then try without HTTPS, if allowed by the admin.
  # only use other port and other SSL mechanism, if it wasn't explicitly set by the user.
  if ( ! isnull( __winrm_port ) )
    return FALSE;

  if ( get_kb_item( "WinRM/default_port" ) != "5985" ) {
    __winrm_fallback_log += 'Applying other default WinRM port 5985 as fallback.\n';
    replace_kb_item( name:"WinRM/default_port", value:"5985" );
    return TRUE;
  }
  return FALSE;
}


# @brief  Set KB-Keys for the successful connection information
#
# @note   This is mainly due to multiple (default) options that exist and iterate
#         through until one fits the bag unless explicitly set by the user
#         This will only really execute on the first successful run. Afterwards,
#           the __winrm global options and resp. KB-Keys will be set already
#           and no the isnull() checks fail.
#
function cache_options_on_success( infos ) {
  local_var infos, new_ssl, ssl;

  if ( isnull( __winrm_ssl ) ) {
    __winrm_ssl = infos["SSL"];
    replace_kb_item( name:"WinRM/ssl", value:infos["SSL"] );
  }

  # nb: was already set, if user-provided
  if ( isnull( __winrm_port ) ) {
    __winrm_port = infos["port"];
    replace_kb_item( name:"WinRM/port", value:infos["port"] );
  }
}


# @brief Interprets the CLIs return, initiates the appropriate feedback, and provides detailed
#       logging for (end-)user debugging purposes
#
# @returns The server-side interpreter output for any successful execution, else NULL
#
function check_result_and_exec_fallback_if_necessary( result, auth_proto, cmd, use_CMD, infos ) {
  local_var auth_proto, cmd, infos, result, use_CMD;
  local_var infos, main_result, port;
  local_var exit_code, cli_output, psrp_result;

  exit_code = result[0];
  cli_output = result[1];
  port = infos["port"];

  if ( exit_code == 0 && winrm_result_doublecheck_needed() ) {
    # Same start for all error cases
    if ( cli_output =~ "^ERROR IN LIBRARY" ) {
      if ( __winrm_internal_error_tracing ) {
        log_message( data:"[TRACING] Overriding exit code from 0 to 1.");
      }
      exit_code = 1;
    }
  }

  if ( __winrm_internal_error_tracing ) {
    if ( exit_code != 0 ) {
      error_message(data:"[TRACING] Found error: full array" + result);
      error_message(data:"[TRACING] Found error: full cli output" + cli_output);
    }
  }

  if ( exit_code == 0 ) {
    cache_options_on_success( infos:infos );
    return cli_output;
  } else if ( exit_code == 2 ) {
    if ( get_kb_item( "WinRM/debug_enabled" ) )
      error_message( data:"A mandatory argument for the WinRM connection was not provided: " + cli_output, port:port );

    set_kb_item( name:"login/WinRM/failure/kind", value:"CLI / library calling" );
    __winrm_local_nonrecoverable_failure = TRUE;
    return;
  } else if ( exit_code != 1 ) {
    if ( get_kb_item( "WinRM/debug_enabled" ) )
      error_message( data:"Unknown error code.", port:port );
    set_kb_item( name:"login/WinRM/failure/kind", value:"Library internals" );
    __winrm_local_nonrecoverable_failure = TRUE;
    return;
  } else if ( exit_code == 1 && strlen(cli_output) < 10 ) {
    # nb: occurs on import errors due to insufficient libraries
    #     no kind of intra-cli fallback will help here
    set_kb_item( name:"login/WinRM/failure", value:TRUE );
    set_kb_item( name:"login/WinRM/failure/kind", value:"CLI / library calling. Potentially missing dependencies" );
    __winrm_local_nonrecoverable_failure = TRUE;
    return;
  }


  psrp_result = split( cli_output, sep:'\n-------\n', keep:FALSE );
  main_result = cli_output;

  local_var main_error, library_error, library_client_args, credential_message_suffix;

  main_error = psrp_result[1];
  library_error = psrp_result[2];
  # nb: password and username are starred out by CLI
  library_client_args = psrp_result[3];
  # nb: Don't use error_message, because fallback may be available.
  __winrm_reason_log += '\nLibrary error message:\n' + library_error;
  __winrm_reason_log += '\nLibrary client arguments:\n' + library_client_args;


  # Perform an early exit without further logging by default about what went wrong
  #   for any VT post winrm_login.nasl
  # For simplicity, do not mark PS usage as generally unrecoverable for this VT.
  # In the future, we may adjust this, if we want more detailed per-VT error logging
  if ( kb_winrm_success() ) {
    if ( get_kb_item( "WinRM/debug_enabled" ) )
      error_message( data:"Intermediate failure for OID: "  + get_script_oid() + '\n' + __winrm_reason_log );

    set_kb_item( name:"login/WinRM/IntermediateFailure", value:get_script_oid() );
    return;
  }

  # nb: Due to the above success check, all the following errors / code are explicitly
  #     only reached during winrm_login.nasl
  #
  #     As a result, __winrm_reason_log suffices since it's appanded there to the
  #     final log message.


  # nb: early exit on non-connection / credential-based issues
  if ( main_result =~ "^ERROR IN LIBRARY / INTERPRETER / COMMAND" ) {
    if ( "Read timed out" ><  library_error ) {
      __winrm_reason_log += '\nWinRM Connection Failure (Read Timeout).';
    } else {
      if ( get_kb_item( "WinRM/debug_enabled" ) )
        log_message( data:'Server PS/CMD interpreter returned an error or some other component produced an unknown fatal error.\n\nIf this is a policy script, please verify all required modules etc. are installed.\n\nPlease contact Greenbone if all verifications were successful and the target is an officially supported system. Full result: ' + main_result, port:port );
      set_kb_item( name:"login/WinRM/failure/kind", value:"PS/CMD interpreter / Server-side / library internals" );
    }
    __winrm_local_nonrecoverable_failure = TRUE;

    if ( kb_winrm_success() ) {
      if ( __winrm_internal_error_tracing )
        error_message( data:"Intermediate failure for OID: "  + get_script_oid() );

      set_kb_item( name:"login/WinRM/IntermediateFailure", value:get_script_oid() );
    }
    return;
  }


  # nb: early exit if disabled by target
  if ( main_result =~ "Received a WSManFault message. \(Code: 5, Machine: [^,]+, Reason: Access is denied." ) {
    __winrm_reason_log += '\nAccess Error.';
    set_kb_item( name:"login/WinRM/failure/kind", value:"WinRM disabled / PowerShell remoting disabled" );
    set_kb_item( name:"login/WinRM/failure", value:TRUE );
    return;
  }

  if ( main_result =~ "Failed to authenticate the user" ) {
    __winrm_reason_log += 'Authentication Error.';
    set_kb_item( name:"login/WinRM/failure/kind", value:"login" );
    set_kb_item( name:"login/WinRM/failure", value:TRUE );
    return;
  }

  ## recoverable errors: SSL, potentially port-based issues
  if ( "CONNECTION REFUSED" >< main_error || "Read timed out" >< library_error ) {
    __winrm_reason_log += '\nTarget refused WinRM connection for the given host, path and port combination.';

    if ( adjust_port_if_fallback_is_possible() ) {
      __winrm_reason_log += '\nConnection error, trying to adjust port and repeat.';
      set_kb_item( name:"login/WinRM/failed/port", value:"5985");
      return _winrm_exec( cmd:cmd, use_CMD:use_CMD, in_fallback:TRUE );
    } else {
      __winrm_reason_log += '\nConnection error and port/SSL adjustments not allowed or unsuccessful as well.';
      set_kb_item( name:"login/WinRM/failure/kind", value:"Connection" );
    __winrm_local_nonrecoverable_failure = TRUE;
    }
  } else if ( "UNKNOWN CONNECTION ERROR" >< main_error ) {
    __winrm_reason_log += '\nCould not create WinRM connection for the given host, path and port combination.';

    if ( adjust_port_if_fallback_is_possible() ) {
      __winrm_reason_log += '\nConnection error, trying to adjust port and repeat.';

      return _winrm_exec( cmd:cmd, use_CMD:use_CMD, in_fallback:TRUE );
    } else {
      __winrm_reason_log += '\nConnection error and port/SSL adjustments not allowed or unsuccessful as well.';
      set_kb_item( name:"login/WinRM/failure/kind", value:"Connection" );
    __winrm_local_nonrecoverable_failure = TRUE;
    }
  } else if ( "SSL FAILURE" >< main_error ) {
    if ( "SSL: WRONG_VERSION_NUMBER" >< library_error ) {
      if ( disable_ssl_if_fallback_is_possible() ) {
        __winrm_reason_log += '\nTarget refused WinRM connection with SSL. Trying to use HTTP and repeat.';
        return _winrm_exec( cmd:cmd, use_CMD:use_CMD, in_fallback:TRUE );
        } else {
        __winrm_reason_log += '\nSSL error. Target refused WinRM connection with SSL enabled. HTTP fallback forbidden or unsuccessful as well.';
        set_kb_item( name:"login/WinRM/failure/kind", value:"SSL" );
      __winrm_local_nonrecoverable_failure = TRUE;
      }
    } else if ( "SSL: CERTIFICATE_VERIFY_FAILED" >< library_error ) {
        __winrm_reason_log += '\nCertificate verification failed. Never falling back to HTTP. If connection to a self-signed HTTPS endpoint is desired, ensure that the certificate is imported on the appliance.';
        set_kb_item( name:"login/WinRM/failure/kind", value:"SSL" );
        __winrm_local_nonrecoverable_failure = TRUE;
    } else {
        __winrm_reason_log += '\nSSL error.';
        set_kb_item( name:"login/WinRM/failure/kind", value:"SSL" );
        __winrm_local_nonrecoverable_failure = TRUE;
    }
  ##### ---- non-recoverable errors ----
  ### Credentials
  # nb: only re-enable once dedicated WinRM credentials exist.
  #
  #if ( get_kb_item( "WinRM/using_SMB_fallback_credentials" ) ) {
  #  credential_message_suffix = " Using the SMB credentials for WinRM as fallback. They may not be valid or intended to be used for this endpoint. To disable this fallback, change the login settings (OID: 1.3.6.1.4.1.25623.1.0.10870).";
  #} else {
  #  credential_message_suffix = "";
  #}
  } else if ( "KRB CRED NOT IN DB" >< main_error ) {
    # to these ecrede
    __winrm_reason_log += '\nWinRM Kerberos credential error. User or domain not fitting to local database.';
    set_kb_item( name:"login/WinRM/failure/kind", value:"login" );
    __winrm_local_nonrecoverable_failure = TRUE;
  } else if ( "KRB PREAUTH FAILURE" >< main_error ) {
    __winrm_reason_log += '\nWinRM (Kerberos) preauthentication error. Possible known causes are: Bad password.';
    set_kb_item( name:"login/WinRM/failure/kind", value:"login" );
    __winrm_local_nonrecoverable_failure = TRUE;
  } else if ( "UNKNOWN KRB FAILURE" >< main_error ) {
    if ( "Configuration file does not specify default realm" >< library_error ) {
      __winrm_reason_log += '\nWinRM Kerberos setup error. Configuration file improperly setup.';
    } else {
      __winrm_reason_log += '\nWinRM Kerberos error.';
    }
    set_kb_item( name:"login/WinRM/failure/kind", value:"login" );
    __winrm_local_nonrecoverable_failure = TRUE;
  ### Connection issues
  } else if ( "WinRM Path not available" >< main_error ) {
    __winrm_reason_log += '\nWinRM HTTP failure: Path not available.';
    set_kb_item( name:"login/WinRM/failure/kind", value:"Connection" );
    __winrm_local_nonrecoverable_failure = TRUE;
  } else if ( "WinRM HTTP Failure" >< main_error ) {
    __winrm_reason_logf += '\nWinRM HTTP failure.';
    set_kb_item( name:"login/WinRM/failure/kind", value:"Connection" );
    __winrm_local_nonrecoverable_failure = TRUE;
  } else if ( "UNKNOWN TRANSPORT ERROR" >< main_error ) {
    __winrm_reason_log += '\nWinRM Transport failure (possibly HTTP failure).';
    set_kb_item( name:"login/WinRM/failure/kind", value:"Connection" );
    __winrm_local_nonrecoverable_failure = TRUE;
  } else if ( "Read timed out" ><  library_error ) {
    __winrm_reason_log += '\nWinRM Connection Failure (Read Timeout). Aborting for this VT.';
    set_kb_item( name:"login/WinRM/failure/kind", value:"Connection" );
    __winrm_local_nonrecoverable_failure = TRUE;
  ### Other
 } else if ( "UNKNOWN" >< main_error ) {
    __winrm_reason_log += '\nUnknown error.';
    set_kb_item( name:"login/WinRM/failure/unknown_failure", value:TRUE );
    __winrm_local_nonrecoverable_failure = TRUE;
  }
  return;
}


# nb: Anybody using the output from this function must work for both
#     SMB-based and WinRM-based LSCs. If this is not possible,
#     We potentially need a second function + migrate some of the callee code to the secondary /
#     a third function combining the former two.

# @brief Returns an array containing all required info to do a connection to a WMI or SMB endpoint.
#
# @return An array containing all required connection info with the following keys and values:
#
#         array["domain"]           -> The user specified domain.
#         array["host"]             -> The IP of the target host.
#         array["hostname"]         -> The hostname of the target host.
#         array["kdc"]              -> The KDC responsible for the target host in an Kerberos enabled environment.
#         array["password"]         -> The user specified password.
#         array["login"]            -> The user specified username.
#         array["port"]             -> The identified port/transport for a SMB connection.
#         array["path"]             -> The (potentially user specified) URL endpoint to use for WinRM
#         array["SSL"]              -> The (potentially user specified) setting of whether to support SSL
#
#         FALSE in the case if any of the required data (host, username or password) is missing in the knowledge base.
#
function kb_winrm_connectinfo() {
  local_var host, hostname, kdc, usrname, passwd, domain, ssl, port, ret;

  host     = get_host_ip();
  hostname = kb_winrm_hostname();
  kdc      = kb_winrm_kdc();
  usrname  = kb_winrm_login();
  passwd   = kb_winrm_password();
  path     = kb_winrm_path();
  ssl      = kb_winrm_ssl();

  if ( ! host )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#winrm_connectinfo" );

  if ( ! hostname )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#hostname#-#winrm_connectinfo" );

  if ( ! kdc )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#kdc#-#winrm_connectinfo" );

  if ( ! usrname )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#usrname#-#winrm_connectinfo" );

  if ( ! passwd )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#passwd#-#winrm_connectinfo" );

  if ( ! path )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#path#-#winrm_connectinfo" );

  if ( ! ssl )  # "no" / "yes"
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ssl#-#winrm_connectinfo" );

  if ( ! host || ! usrname || ! passwd )
    return FALSE;

  domain = kb_winrm_domain();
  port = kb_winrm_port();

  ret = make_array();
  ret["domain"]           = domain;
  ret["host"]             = host;
  ret["hostname"]         = hostname;
  ret["kdc"]              = kdc;
  ret["password"]         = passwd;
  ret["login"]            = usrname;
  ret["port"]             = port;
  ret["path"]             = path;
  ret["SSL"]              = ssl;

  return ret;
}


# @brief Parses the main WinRM credentials and if fallback enabled any SMB
#        credentials.
#
# @note   Currently supports Kerberos and NTLM. Transfers SMB settings to WinRM-equivalent
#         If reasonable
#
# @return credential type used ("Kerberos" / "NTLM")
#
function parse_winrm_credentials() {
  local_var login, password, user_domain, host, matched_domain, fqdn_domain, port, path, kdc, credential_type;

  # nb: to-be mode into winrm_{ntlm,krb5}_authorization.nasl once credentials are added

  if ( get_kb_item( "WinRM/KRB5/login_filled/0" ) ) {
    login       = string( get_kb_item( "WinRM/KRB5/login_filled/0" ) );
    password    = string( get_kb_item( "WinRM/KRB5/password_filled/0" ) );
    user_domain = string( get_kb_item( "WinRM/KRB5/realm_filled/0" ) );
    kdc         = string( get_kb_item( "WinRM/KRB5/kdc_filled/0" ) );
    credential_type = "Kerberos";
  } else if ( get_kb_item( "WinRM/NTLM/login_filled/0" ) ) {
    login       = string( get_kb_item( "WinRM/NTLM/login_filled/0" ) );
    password    = string( get_kb_item( "WinRM/NTLM/password_filled/0" ) );
    user_domain = string( get_kb_item( "WinRM/NTLM/domain_filled/0" ) );
    credential_type = "NTLM";
  } else if ( get_kb_item("WinRM/fallback_to_smb_credentials" ) ) {
    # nb: no need to add smb_login.nasl as dependency, if parsing
    #     here.
    if ( get_kb_item( "KRB5/login_filled/0" ) ) {
      login       = string( get_kb_item( "KRB5/login_filled/0" ) );
      password    = string( get_kb_item( "KRB5/password_filled/0" ) );
      user_domain = string( get_kb_item( "KRB5/realm_filled/0" ) );
      kdc         = string( get_kb_item( "KRB5/kdc_filled/0" ) );
      credential_type = "Kerberos";
      # for more transparent error-messages
      set_kb_item( name:"WinRM/using_SMB_fallback_credentials", value:TRUE );
    } else if ( get_kb_item( "SMB/login_filled/0" ) ) {
      # NTLM
      login       = string( get_kb_item( "SMB/login_filled/0" ) );
      password    = string( get_kb_item( "SMB/password_filled/0" ) );
      user_domain = string( get_kb_item( "SMB/domain_filled/0" ) );
      credential_type = "NTLM";
      set_kb_item( name:"WinRM/using_SMB_fallback_credentials", value:TRUE );
    }

    # nb: According to https://github.com/jborean93/pypsrp/blob/master/src/pypsrp/wsman.py#L788-L794
    #     messages are never send in cleartext by default if not already using HTTPS
    #     including, if NTLM is used as auth mechanism.
    #     Thus, SMB/dont_send_in_cleartext  can be ignored.

  } else {
    __winrm_reason_log += "No dedicated WinRM credentials were available and fallback to SMB disabled. WinRM login will fail.";
    login = "";
    password = "";
    user_domain = "";
    credential_type = "Unknown";
    return credential_type;
  }

  set_kb_item( name:"WinRM/credential_type", value:credential_type );


  if ( defined_func( "ip_reverse_lookup" ) )
    host = ip_reverse_lookup();

  if ( ! user_domain ) {
    if ( '\\' >< login ) {
      matched_domain = eregmatch( pattern:".*\\", string:login );
      if ( ! isnull( matched_domain[0] ) )
        user_domain = ereg_replace( pattern:"\\", replace:"", string:matched_domain[0] );
    }

    if ( '@' >< login ) {
      matched_domain = eregmatch( pattern:"@.*", string:login );
      if ( ! isnull( matched_domain[0] ) ) {
        user_domain = ereg_replace( pattern:"@", replace:"", string:matched_domain[0] );
        if ( user_domain =~ ".*\..*" ) {
          fqdn_domain = eregmatch( pattern:".*\.$", string:user_domain );
          if ( ! isnull( fqdn_domain[0] ) )
            user_domain = ereg_replace( pattern:"\.$", replace:"", string:fqdn_domain[0] );
        }
      }
    }
  }

  if ( '\\' >< login ) {
    user_login = eregmatch( pattern:"\\.*", string:login );
    if ( '\\' >< user_login[0] ) {
      login = ereg_replace( pattern:"\\", replace:"", string:user_login[0] );
    }
  }

  if ( '@' >< login ) {
    user_login = eregmatch( pattern:".*@", string:login );
    if ( '@' >< user_login[0] ) {
      login = ereg_replace( pattern:"@", replace:"", string:user_login[0] );
    }
  }

  if ( ! strlen( login ) )
    login = "";
  if ( ! strlen( password ) )
    password = "";

  # nb: ensure global vars are set, since
  #     the main initiator script also wants to test the login.
  replace_kb_item( name:"WinRM/login", value:login );
  __winrm_login = login;
  replace_kb_item( name:"WinRM/password", value:password );
  __winrm_password = password;

  port = string( get_kb_item( "WinRM/port_filled/0" ) );
  if ( ! port ) {
    # HTTPS default -> 5986 initially, 5985 only during fallback
    replace_kb_item( name:"WinRM/default_port", value:"5986" );
  } else {
    replace_kb_item( name:"WinRM/port", value:port );
    __winrm_port = port;
  }

  path = string( get_kb_item( "WinRM/path_filled/0" ) );
  if ( ! path ) {
    path = "wsman";
  }
  replace_kb_item( name:"WinRM/path", value:path );
  __winrm_path = path;

  if ( host ) {
    replace_kb_item( name:"WinRM/hostname", value:host );
    __winrm_host = host;
  }

  if ( kdc ) {
    replace_kb_item( name:"WinRM/kdc", value:kdc );
    __winrm_kdc = kdc;
  }

  if ( strlen( user_domain ) ) {
    replace_kb_item( name:"WinRM/domain", value:user_domain );
    __winrm_domain = user_domain;
  }
  return credential_type;
}


# @brief  Sets up kerberos context for WinRM-allowed credentials.
#
# @note   Since both Kerberos and NTLM credentials may exist
#         and NTLM used as fallback
#         Will only successfully prepare once per NASL script by default.
#           Use force_prepare if want to override.
#         nb: Anything kerberos will be cleared after each NASL script!
# @return NULL if insufficient kerberos credentials exist
#         TRUE on success, FALSE otherwise
#
function prepare_kerberos( force_prepare ) {
  local_var force_prepare;

  if ( __winrm_krb_prepared && ! force_prepare )
    return TRUE;

  local_var domain, host, infos, kdc, login, passwd;
  local_var context, result;
  infos = kb_winrm_connectinfo();
  kdc = infos["kdc"];
  host = infos["host"];
  domain = infos["domain"];
  login = infos["login"];
  passwd = infos["password"];

  if ( kdc && host && defined_func( "krb5_gss_init" ) ) {

    if ( isnull( login ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#login#-#prepare_kerberos" );
    if ( isnull( passwd ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#passwd#-#prepare_kerberos" );
    if ( isnull( domain ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#domain#-#prepare_kerberos" );
    if ( isnull( kdc ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#kdc#-#prepare_kerberos" );
    if ( isnull( host ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#prepare_kerberos" );

    result = krb5_gss_init();

    # nb:
    # gss_prepare_context creates the following krb5conf if not provided with a config_path
    # arg. As a result, no default REALM parameter is given in the cfg.
    # [realms]
    # redacted_realm_name = {
    # kdc = redacted
    # admin_server = redacted
    # master_kdc = redacted
    # }

    context = krb5_gss_prepare_context( kdc:kdc, realm:domain, host:host, service:"cifs", user:login, password:passwd );
    if ( krb5_is_failure( context ) ) {
      return FALSE;
    }
    result = krb5_gss_update_context();
    if ( krb5_is_failure( result ) ) {
      return FALSE;
    }
    krb5_gss_update_context_out();
    __winrm_krb_prepared = TRUE;
    return TRUE;
  }
  return;
}


# @brief Returns the known or current default TCP port.
#        If the port is explicitly known, the value is cached in a global variable to avoid
#        another access to the DB.
#
#
# @return Always returns the known or default port for the current endpoint.
#
function kb_winrm_port() {
  if ( ! isnull( __winrm_port ) )
    return __winrm_port;

  local_var port;
  if ( port = get_kb_item( "WinRM/port" ) ) {
    __winrm_port = port;
    return port;
  }

  return get_kb_item( "WinRM/default_port" );
}


# @brief Returns the known or current default SSL status for the WinRM endpoint.
#        If the status is explicitly known, the value is cached in a global variable to avoid
#        another access to the DB.
#
#
# @return Always returns the known or current default SSL state for the current endpoint.
#
function kb_winrm_ssl() {
  if ( ! isnull( __winrm_ssl ) ){
    return __winrm_ssl;
  }

  local_var ssl;
  if ( ssl = get_kb_item( "WinRM/ssl" ) ) {
    #ssl = ssl == "yes";

    __winrm_ssl = ssl;
    return __winrm_ssl;
  } else {
    # nb: safety measure, in case anything odd happens
    if ( isnull ( ssl = get_kb_item( "WinRM/default_ssl" ) ) )
      ssl = "yes";

    return ssl;
  }
}


# @brief Returns the known path.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @note The return value could be NULL if no entry is found.
#
# @return Always returns the known path for the current server.
#
function kb_winrm_path() {
  if ( ! isnull( __winrm_path ) )
    return __winrm_path;

  __winrm_path = get_kb_item( "WinRM/path" );
  return __winrm_path;
}


# @brief Returns the known kerberos domain for the WinRM endpoint.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @note The return value could be NULL if no entry is found.
#
# @return Always returns the known endpoint for the current server.
#
function kb_winrm_domain() {
  if ( ! isnull( __winrm_domain ) )
    return __winrm_domain;

  __winrm_domain = get_kb_item( "WinRM/domain" );
  return __winrm_domain;
}


# @brief Returns the known kerberos KDC for the WinRM endpoint.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @note The return value could be NULL if no entry is found.
#
# @return Always returns the known KDC for the current server.
#
function kb_winrm_kdc() {
  if ( ! isnull( __winrm_kdc ) )
    return __winrm_kdc;

  __winrm_kdc = get_kb_item( "WinRM/kdc" );
  return __winrm_kdc;
}


# @brief Returns the known host
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @note If no entry is found, it will use the result of ip_reverse_lookup()
#
# @return Always returns the known hostname for the current server.
function kb_winrm_hostname() {
  if ( ! isnull( __winrm_host ) )
    return __winrm_host;

  # no need to do multiple ip_reverse_lookup() calls
  if ( __winrm_hostname_permanently_null )
    return;

  local_var host;
  if ( host = get_kb_item( "WinRM/hostname" ) ) {
    __winrm_host = host;
    return host;
  }

  if ( defined_func( "ip_reverse_lookup" ) )
    host = ip_reverse_lookup();

  if ( ! isnull( host ) ) {
    set_kb_item( name:"WinRM/hostname", value:host );
    __winrm_host = host;
  } else {
    __winrm_hostname_permanently_null = TRUE;
  }
  return host;
}


# @brief Returns the known username
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @note The return value could be NULL if no entry is found.
#
# @return Always returns the known username for the current server.
function kb_winrm_login() {
  if ( ! isnull( __winrm_login ) )
    return __winrm_login;

  __winrm_login = get_kb_item( "WinRM/login" );
  return __winrm_login;
}


# @brief Returns the known password
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @note The return value could be NULL if no entry is found.
#
# @return Always returns the known password for the current server.
function kb_winrm_password() {
  if ( ! isnull( __winrm_password ) )
    return __winrm_password;

  __winrm_password = get_kb_item( "WinRM/password" );
  return __winrm_password;
}

# @brief Returns whether WinRM is known to have fully failed previously.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @note  Should be NULL if not all options were exhausted yet.
#
# @return Returns TRUE if no more WinRM connection should be attempted
function kb_winrm_failure() {
  if ( ! isnull( __winrm_failure ) )
    return __winrm_failure;

  __winrm_failure = get_kb_item( "WinRM/failure" );
  return __winrm_failure;
}


# @brief Returns whether WinRM is known to have succeeded previously.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @note  Should be NULL if not all options were exhausted yet.
#
# @return Returns TRUE if a WinRM connection was successfully made previously.
function kb_winrm_success() {
  if ( ! isnull( __winrm_success ) )
    return __winrm_success;

  __winrm_success = get_kb_item( "login/WinRM/success" );
  return __winrm_success;
}


# @brief Returns whether WinRM is known to have succeeded previously via Kerberos.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @return Returns TRUE if a WinRM connection authenticated via Kerberos
#         was successfully made previously.
function kb_winrm_krb_success() {
  if ( ! isnull( __winrm_krb_success ) )
    return __winrm_krb_success;

  __winrm_krb_success = get_kb_item( "login/WinRM/Kerberos/success" );
  return __winrm_krb_success;
}


# @brief Returns whether WinRM is known to have succeeded previously via NTLM.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @return Returns TRUE if a WinRM connection authenticated via NTLM
#         was successfully made previously.
function kb_winrm_ntlm_success() {
  if ( ! isnull( __winrm_ntlm_success ) )
    return __winrm_ntlm_success;

  __winrm_ntlm_success = get_kb_item( "login/WinRM/NTLM/success" );
  return __winrm_ntlm_success;
}


# @brief Returns whether a fallback from KRB to NTLM credentials is allowed.
#        If it is the first time the value is cached in a global variable to avoid
#        another access to the DB.
#
# @return Always returns the same option for the current scan config.
function kb_winrm_disable_krb_to_ntlm_fallback() {
  if ( ! isnull( __winrm_disable_KRB_to_NTLM_fallback ) )
    return __winrm_disable_KRB_to_NTLM_fallback;

  __winrm_disable_KRB_to_NTLM_fallback = get_kb_item( "WinRM/disable_krb_to_ntlm_fallback" );
  return __winrm_disable_KRB_to_NTLM_fallback;
}


# @brief Checks, whether WinRM ports are enabled
#
# @note If a user explicitly set a WinRM port, we assume it should be used
#       Caches the result of port state requests in KB-Key and generally
#       in global var to reduce overhead.
#
# @return boolean status representing, whether the port is open / explicitly set by user
function kb_check_winrm_ports() {
  if ( ! isnull( __winrm_ports_enabled ) )
    return __winrm_ports_enabled;

  if ( __winrm_ports_enabled = get_kb_item( "WinRM/enabled_ports" ) )
    return __winrm_ports_enabled;

  if ( kb_winrm_port() || get_port_state( 5985 ) || get_port_state( 5986 )  ) {
    __winrm_ports_enabled = TRUE;
    set_kb_item( name:"WinRM/enabled_ports", value:TRUE );
  } else {
    if ( isnull( get_kb_item( "login/WinRM/failure/reason" ) ) )
      set_kb_item( name:"login/WinRM/failure/reason", value:"Insufficient ports enabled" );
  }
  return __winrm_ports_enabled;
}


# @brief Checks, whether SMB ports are enabled & open
#
# @note Roughly same internal check as kb_smb_transport(), however does not cause exit( 0 )
#
# @return boolean status representing, whether an SMB connection is possible & allowed
#
function kb_check_smb_ports() {
  if ( ! isnull( __winrm_smb_ports_enabled ) )
    return __winrm_smb_ports_enabled;

  if ( __winrm_smb_ports_enabled = get_kb_item( "WinRM/SMB/enabled_ports" ) )
    return __winrm_smb_ports_enabled;

  local_var transport;
  if ( isnull( transport = get_kb_item( "SMB/transport" ) ) )
    transport = 445;

  __winrm_smb_ports_enabled = get_port_state( transport );
  set_kb_item( name:"WinRM/SMB/enabled_ports", value:__winrm_smb_ports_enabled );
  return __winrm_smb_ports_enabled;
}


# @brief  Shortcut to all checks that cause early-exits if WinRM is known
#         to fail already
#
# @returns FALSE if known to fail / not supposed to run based on port lists etc.
#           else TRUE
function can_run_winrm() {
  if ( ! isnull( __winrm_can_run ) )
    return __winrm_can_run;

  if ( ! isnull( can_run = get_kb_item( "WinRM/can_run" ) ) ) {
    __winrm_can_run = can_run == "yes";
  }

  if ( defined_func( "psrp_cli" ) && kb_check_winrm_ports() && ! kb_winrm_failure() &&  kb_winrm_connectinfo() ) {
    # replace instead of set to be safe against host-name forking + race condition
    __winrm_can_run = TRUE;
    replace_kb_item( name:"WinRM/can_run", value:"yes" );
  } else {
    __winrm_can_run = FALSE;
    replace_kb_item( name:"WinRM/can_run", value:"no" );
  }

  return __winrm_can_run;
}


# @brief  Shortcut to check, whether WinRM is known to fail in this VT
#         only (intermediate failure)
#
# @returns TRUE if known to fail
#
function kb_winrm_failure_for_this_vt() {
  return ! isnull( __winrm_local_nonrecoverable_failure );
}


# @brief  Shortcut to check, whether double-check of stdout
#         for error is necessary.
#
# @returns TRUE output should always be scanned, irrespective
#           of returned error-code
#
function winrm_result_doublecheck_needed() {
  if ( ! isnull( __winrm_result_double_check ) ) {
    return __winrm_result_double_check;
  }

  local_var result_double;

  result_double = get_kb_item( "WinRM/result_double_check" );
  __winrm_result_double_check = result_double == "yes";
  return __winrm_result_double_check;
}
