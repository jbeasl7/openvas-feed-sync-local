# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103697");
  script_version("2025-04-07T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-04-07 05:39:52 +0000 (Mon, 07 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-04-15 10:23:42 +0200 (Mon, 15 Apr 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Options for Brute Force NVTs");
  script_category(ACT_SETTINGS);
  script_family("Settings");
  script_copyright("Copyright (C) 2013 Greenbone AG");

  script_add_preference(name:"Credentials file:", value:"", type:"file", id:1);
  script_add_preference(name:"Use only credentials listed in uploaded file:", type:"checkbox", value:"yes", id:2);
  script_add_preference(name:"Disable brute force checks", type:"checkbox", value:"no", id:3);
  script_add_preference(name:"Disable default account checks", type:"checkbox", value:"no", id:4);

  script_tag(name:"summary", value:"This VT sets some options for the brute force / default
  credentials checks.

  - Disable brute force checks:

  Disables the brute force checks done by the following VTs:

  HTTP Brute Force Logins With Default Credentials (OID: 1.3.6.1.4.1.25623.1.0.108041)

  SSH Brute Force Logins With Default Credentials (OID: 1.3.6.1.4.1.25623.1.0.108013)

  SMB Brute Force Logins With Default Credentials (OID: 1.3.6.1.4.1.25623.1.0.804449)

  Check default community names of the SNMP Agent (OID: 1.3.6.1.4.1.25623.1.0.103914).

  - Disable default account checks:

  Disables all VTs checking for default accounts (Mainly from the 'Default Accounts' family).

  - Credentials file:

  A file containing a list of credentials. One username/password pair per line. Username and
  password are separated by ':'. Please use '<<none>>' for empty passwords or empty usernames. If
  the username or the password contains a ':', please escape it with '\:'.

  Examples:

  user:userpass

  user1:userpass1

  <<none>>:userpass2

  user3:<<none>>

  user4:pass\:word

  user5:userpass5

  Optionally the protocol/service for which the check applies can be passed. For these the
  additional string 'custom' is required / needs to be added.

  Examples:

  user:userpass:custom:all

  user:userpass:custom:ssh

  user:userpass:custom:ssh,ftp

  Current supported protocols/services are:

  all

  ftp

  ssh

  http

  - Use only credentials listed in uploaded file:

  Use only the credentials that are listed in the uploaded file. The internal default credentials
  are ignored.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("list_array_func.inc");

DEBUG = FALSE;

disable_bf = script_get_preference( "Disable brute force checks", id:3 );
if( "yes" >< disable_bf )
  set_kb_item( name:"default_credentials/disable_brute_force_checks", value:TRUE );

disable_da = script_get_preference( "Disable default account checks", id:4 );
if( "yes" >< disable_da )
  set_kb_item( name:"default_credentials/disable_default_account_checks", value:TRUE );

if( ! COMMAND_LINE )
  credentials_list = script_get_preference_file_content( "Credentials file:", id:1 );
else
  credentials_list = get_kb_item( "default_credentials/command_line_credentials_list" );

if( ! credentials_list )
  exit( 0 );

# nb: Used for later cross-checking / verification
allowed_service = make_list(
  "all",
  "ftp",
  "http",
  "ssh"
);

credentials_lines = split( credentials_list, keep:FALSE );

invalid_lines_reporting = 'The following invalid lines have been found in the uploaded credentials file. Scanner will not use them. Please check the VT description for the correct syntax.\n';

foreach line( credentials_lines ) {

  if( DEBUG ) display( "DEBUG: Current evaluated line is '" + line + "'" );

  # nb:
  # - ';' was used pre r9566 but was changed to ':' as a separator as the GSA had stripping ';' from
  #   the VT description in the past. Keeping both in here for backwards compatibility with older
  #   scan configs.
  # - This is only the first basic check, more extended ones are done later.
  if( line !~ "^.+;.+$" && line !~ "^.+:.+$" ) {
    invalid_lines_reporting += '\n  ' + line + " (Hint: Missing ':' separator)";
    invalid_line_found = TRUE;
    continue;
  }

  # nb for some items below:
  # - Make sure to have the same syntax / fields like in default_credentials.inc
  # - The "all" is used in default_ssh_credentials.nasl and default_http_auth_credentials.nasl
  #   to decide if the credential should be used.
  # - The "custom" string is used in/for gb_default_ftp_credentials.nasl because we currently don't
  #   want to run gb_default_ftp_credentials.nasl against all credentials from the
  #   default_credentials.inc
  # - As the script_preferences handling is quite rudimentary we need to do some best guess on the
  #   syntax checks below

  semicolon_check = split( line, sep:";", keep:FALSE );
  semicolon_entries = max_index( semicolon_check );
  double_dot_check = split( line, sep:":", keep:FALSE );
  double_dot_entries = max_index( double_dot_check );

  # nb: Just the simplest cases like "user;userpass"
  if( semicolon_entries == 2 ) {
    line += ";custom;all";
  }

  # or "user:userpass"
  else if( double_dot_entries == 2 ) {
    line += ":custom:all";
  }

  # or "user;userpass;custom;all" but without an escaped ";"
  else if( semicolon_entries == 4 && "\;" >!< line ) {
    type = semicolon_check[2];
    service = semicolon_check[3];
  }

  # or "user:userpass:custom:all" but without an escaped ":"
  else if( double_dot_entries == 4 && "\:" >!< line ) {
    type = double_dot_check[2];
    service = double_dot_check[3];
  }

  # nb:
  # - More complex parsing
  # - Parsing only on a best guess (e.g. no mixture of "\:" or "\;" and the like)
  else {

    if( "\;" >< line && semicolon_entries >= 4 ) {
      type = semicolon_check[semicolon_entries - 2];
      service = semicolon_check[semicolon_entries - 1];
    }

    else if( "\:" >< line && double_dot_entries >= 4 ) {
      type = double_dot_check[double_dot_entries - 2];
      service = double_dot_check[double_dot_entries - 1];
    }

    else if( ( "\;" >!< line && semicolon_entries == 3 ) ||
             ( "\:" >!< line && double_dot_entries == 3 )
           ) {
      invalid_lines_reporting += '\n  ' + line + " (Hint: Possible missing service)";
      invalid_line_found = TRUE;
      continue;
    }

    # nb: Next two should be fine for now (best guess)
    else if( "\;" >< line && semicolon_entries == 3 ) {
      line += ";custom;all";
    }

    else if( "\:" >< line && double_dot_entries == 3 ) {
      line += ":custom:all";
    }

    # nb: Not sure how to handle so just ignore for now...
    else {
      invalid_lines_reporting += '\n  ' + line + " (Unknown/Unhandled line)";
      invalid_line_found = TRUE;
      continue;
    }
  }

  if( type && type != "custom" ) {
    invalid_lines_reporting += '\n  ' + line + " (Hint: Unsupported '" + type + "' string found, only allowed: 'custom')";
    invalid_line_found = TRUE;
    continue;
  }

  if( service ) {
    service_split = split( service, sep:",", keep:FALSE );
    invalid_subline_found = FALSE;
    foreach service_line( service_split ) {
      if( ! in_array( search:service_line, array:allowed_service, part_match:FALSE, icase:FALSE ) ) {
        invalid_lines_reporting += '\n  ' + line + " (Hint: Unsupported '" + service_line + "' string found, only allowed is a single or a combination of these: '" + join( list:allowed_service, sep:"," ) + "')";
        invalid_line_found = TRUE;
        invalid_subline_found = TRUE;
      }
    }

    # nb: Completely ignore this one
    if( invalid_subline_found )
      continue;
  }

  if( DEBUG ) display( "DEBUG: Final line is '" + line + "'" );

  set_kb_item( name:"default_credentials/credentials", value:line );
}

uploaded_credentials_only = script_get_preference( "Use only credentials listed in uploaded file:", id:2 );
if( "yes" >< uploaded_credentials_only || "no" >< uploaded_credentials_only )
  set_kb_item( name:"default_credentials/uploaded_credentials_only", value:uploaded_credentials_only );

if( invalid_line_found )
  log_message( port:0, data:invalid_lines_reporting );

exit( 0 );
