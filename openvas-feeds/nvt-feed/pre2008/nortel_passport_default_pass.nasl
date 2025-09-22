# SPDX-FileCopyrightText: 2002 Rui Bernardino
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10989");
  script_version("2023-09-07T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-07 05:05:21 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Nortel/Bay Networks Default Password (Telnet)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Rui Bernardino");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/nortel_bay_networks/device/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Telnet this switch/router and change all passwords (check the
  manual for default users).");

  script_tag(name:"summary", value:"The remote switch/router uses the default password.");

  script_tag(name:"impact", value:"This means that anyone who has (downloaded) a user manual can
  telnet to it and gain administrative access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );

banner = telnet_get_banner( port:port );
if( ! banner || "Passport" >!< banner || "NetLogin:" >!< banner )
  exit( 0 );

# Although there are at least 11 (!?) default passwords to check, the passport will only allow
# 3 attempts before closing down the telnet port for 60 seconds. Fortunately, nothing prevents
# you to establish a new connection for each password attempt and then close it before the 3 attempts.

creds = make_array(
"rwa", "rwa",
"rw", "rw",
"l3", "l3",
"l2", "l2",
"ro", "ro",
"l1", "l1",
"l4admin", "l4admin",
"slbadmin", "slbadmin",
"operator", "operator",
"l4oper", "l4oper",
"slbop", "slbop" );

report = 'The following default credentials were identified: (user:pass)\n';

foreach cred( keys( creds ) ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );
  buf = telnet_negotiate( socket:soc );

  if( "NetLogin:" >< buf ) {
    close( soc );
    exit( 0 );
  }

  if( "Passport" >< buf && "Login:" >< buf ) {
    test = string( cred, "\n", creds[cred], "\n" );
    send( socket:soc, data:test );
    resp = recv( socket:soc, length:1024 );

    if( "Access failure" >< resp ) {
      close( soc );
      break;
    }

    if( ! ( "Login" >< resp ) ) {
      VULN = TRUE;
      report += '\n' + cred + ":" + creds[cred];
    }
  } else {
    close( soc );
    break;
  }
  close( soc );
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
