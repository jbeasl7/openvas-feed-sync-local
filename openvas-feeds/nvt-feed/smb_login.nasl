# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10394");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2008-09-10 10:22:48 +0200 (Wed, 10 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_name("SMB log in");
  script_dependencies("smb_authorization.nasl", "krb5_authorization.nasl", "netbios_name_get.nasl",
                      "lsc_options.nasl", "cifs445.nasl", "find_service.nasl", "logins.nasl",
                      "global_settings.nasl");
  script_require_keys("SMB/name", "SMB/transport");
  script_exclude_keys("global_settings/authenticated_scans_disabled");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script attempts to logon into the remote host using
  login/password credentials.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

if( get_kb_item( "global_settings/authenticated_scans_disabled" ) )
  exit( 0 );

include("smb_nt.inc");
include("host_details.inc");

function remote_login( login, passwd, domain, name, port, host, kdc ) {

  local_var login, passwd, domain, name, port, host, kdc;
  local_var login_defined, soc, info;

  login_defined = 0;

  soc = open_sock_tcp( port );
  if( ! soc ) {
    return login_defined;
  }

  if( host && kdc ) {
    info = smb_login_and_get_tid_uid( soc:soc, name:name, login:login, passwd:passwd, domain:domain, share:"IPC$", kdc:kdc, host:host );
  } else {
    info = smb_login_and_get_tid_uid( soc:soc, name:name, login:login, passwd:passwd, domain:domain, share:"IPC$" );
  }

  if( isnull( info ) ) {
    login_defined = 0;
  } else {
    login_defined = 1;
  }

  close( soc );

  return login_defined;
}

port = kb_smb_transport();
if( ! port ) port = 139;
if( ! get_port_state( port ) ) exit( 0 );

name = kb_smb_name();
if( ! name ) name = "*SMBSERVER";

if( get_kb_item( "KRB5/login_filled/0" ) ) {
  login       = string( get_kb_item( "KRB5/login_filled/0" ) );
  password    = string( get_kb_item( "KRB5/password_filled/0" ) );
  user_domain = string( get_kb_item( "KRB5/realm_filled/0" ) );
  kdc         = string( get_kb_item( "KRB5/kdc_filled/0" ) );
  if( defined_func( "ip_reverse_lookup" ) ) {
    host = ip_reverse_lookup();
  }
} else {
  login       = string( get_kb_item( "SMB/login_filled/0" ) );
  password    = string( get_kb_item( "SMB/password_filled/0" ) );
  user_domain = string( get_kb_item( "SMB/domain_filled/0" ) );
}

if( ! user_domain ) {

  if( '\\' >< login ) {
    matched_domain = eregmatch( pattern:".*\\", string:login );
    if( ! isnull( matched_domain[0] ) ) {
      user_domain = ereg_replace( pattern:"\\", replace:"", string:matched_domain[0] );
    }
  }

  if( '@' >< login ) {
    matched_domain = eregmatch( pattern:"@.*", string:login );
    if( ! isnull( matched_domain[0] ) ) {
      user_domain = ereg_replace( pattern:"@", replace:"", string:matched_domain[0] );
      if( user_domain =~ ".*\..*" ) {
        fqdn_domain = eregmatch( pattern:".*\.$", string:user_domain );
        if( ! isnull( fqdn_domain[0] ) ) {
          user_domain = ereg_replace(pattern:"\.$", replace:"", string:fqdn_domain[0]);
        }
      }
    }
  }
}

if( '\\' >< login ) {
  user_login = eregmatch( pattern:"\\.*", string:login );
  if( '\\' >< user_login[0] ) {
    login = ereg_replace( pattern:"\\", replace:"", string:user_login[0] );
  }
}

if( '@' >< login ) {
  user_login = eregmatch( pattern:".*@", string:login );
  if( '@' >< user_login[0] ) {
    login = ereg_replace( pattern:"@", replace:"", string:user_login[0] );
  }
}

if( ! strlen( login ) )     login = "";
if( ! strlen( password ) )  password = "";
if( strlen( user_domain ) ) domain = user_domain;

if( ! strlen( user_domain ) ) {
  #user_domain = "";
  #soc = open_sock_tcp( port );
  #if( ! soc ) exit( 0 );
  #
  #smb_session_request( soc:soc, remote:name );

  #prot = smb_neg_prot( soc:soc );
  #close( soc );

  #domain = smb_neg_prot_domain( prot:prot );
  flag = 1;

  domain = string( get_kb_item( "SMB/DOMAIN" ) );
  if( ! domain ) domain = string( get_kb_item( "SMB/workgroup" ) );
  if( ! domain ) domain = "";
}

set_kb_item( name:"SMB/login", value:login );
set_kb_item( name:"SMB/password", value:password );

if( host ) {
  set_kb_item( name:"SMB/hostname", value:host );
}

if( domain && flag != 1 ) {
  set_kb_item( name:"SMB/domain", value:domain );
}

protocol_info = "";

if( defined_func( "krb5_gss_init" ) ) {
  if( flag == 1 && ! strlen( user_domain ) ) {
    login_defined = remote_login( login:login, passwd:password, domain:"", name:name, port:port, host:host, kdc:kdc );
  } else {
    login_defined = remote_login( login:login, passwd:password, domain:domain, name:name, port:port, host:host, kdc:kdc);
  }

  # n.b. Pre-Check to determine if Kerberos login was successful or we need to try NTLMSSP
  if( login_defined == 1 && host && kdc ) {
    # Case 1, Login was successful and host has been resolved and KDC is defined --> Kerberos is enabled and working
    protocol_info = " via the given Kerberos credentials and Kerberos protocol";
    set_kb_item( name:"login/SMB/kerberos/success", value:TRUE );
  } else if( login_defined == 0 && host && kdc ) {
    # Case 2, Login failed but necessary Kerberos parameters have been set/resolved --> Retry but without these parameters to force NTLMSSP
    # Can happen if the user supplies a complete Kerberos enabled credential set for a target that does not support Kerberos
    if( flag == 1 && ! strlen( user_domain ) ) {
      login_defined = remote_login( login:login, passwd:password, domain:"", name:name, port:port );
    } else {
      login_defined = remote_login( login:login, passwd:password, domain:domain, name:name, port:port );
    }
    protocol_info = " via the given Kerberos credentials, when trying them for the NTLM protocol as fallback.";
    protocol_info += '\n\nNote: A prior attempt to login via the Kerberos protocol failed';

  } else if( get_kb_item( "SMB/login_filled/0" ) ) {
    # Case 3, Scanner has Kerberos support but NTLM credentials were supplied
    protocol_info = " via the given NTLM credentials and NTLM protocol";
  }

  if( krb5_is_failure() ) {
    krb5_error_code = krb5_error_code_to_string();
    protocol_info += ". KRB5 error code: " + krb5_error_code;
    set_kb_item( name:"login/SMB/krb5_error_code", value:krb5_error_code );
  }

} else {
  if( flag == 1 && ! strlen( user_domain ) ) {
    login_defined = remote_login( login:login, passwd:password, domain:"", name:name, port:port );
  } else {
    login_defined = remote_login( login:login, passwd:password, domain:domain, name:name, port:port );
  }
  protocol_info = " via the given credentials and NTLM protocol.";
  protocol_info += '\n\nNote: The Kerberos implementation is not available on this scanner version';
}

if( login_defined == 1 ) {
  reason = "It was possible to log into the remote host using the SMB protocol" + protocol_info + ".";
  register_host_detail( name:"Auth-SMB-Success", value:"Protocol SMB, Port " + port + ", User " + login );
  log_message( port:port, data:reason );
  set_kb_item( name:"login/SMB/success", value:TRUE );
  set_kb_item( name:"login/SMB/success/port", value:port );
  set_kb_item( name:"login/SMB/success/reason", value:reason );
}

else if( ( login_defined == 0 ) && login ) {
  reason = "It was NOT possible to log into the remote host using the SMB protocol" + protocol_info + ".";
  register_host_detail( name:"Auth-SMB-Failure", value:"Protocol SMB, Port " + port + ", User " + login );
  log_message( port:port, data:reason );
  set_kb_item( name:"login/SMB/failed", value:TRUE );
  set_kb_item( name:"login/SMB/failed/port", value:port );
  set_kb_item( name:"login/SMB/failed/reason", value:reason );
}

exit( 0 );
