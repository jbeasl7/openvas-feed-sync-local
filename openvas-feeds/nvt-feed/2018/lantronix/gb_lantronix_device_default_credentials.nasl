# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107329");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-07-12 18:29:24 +0200 (Thu, 12 Jul 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2018-14018");

  script_name("Lantronix Devices Default Credentials (Telnet)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_lantronix_device_consolidation.nasl",
                      "gb_default_credentials_options.nasl");
  script_mandatory_keys("lantronix_device/telnet/detected");
  script_require_ports("Services/telnet", 9999);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Lantronix devices have a default useraccount 'root' with
  password 'system' which grants admin rights access via Telnet.");

  script_tag(name:"vuldetect", value:"Tries to login using default credentials via Telnet.");

  script_tag(name:"impact", value:"Using the command 'set privilege' followed by entering the
  password 'system' enables the attacker to gather information, change configurations, telnet to
  other hosts etc.");

  script_tag(name:"affected", value:"Lantronix devices with Telnet access enabled.");

  script_tag(name:"solution", value:"Consult your documentation how to change default credentials
  and/or disable remote access to the device.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include( "host_details.inc" );

port = get_kb_item( "lantronix_device/telnet/port" );
if( ! get_kb_item("lantronix_device/telnet/" + port + "/access") )
  exit ( 0 );

soc = open_sock_tcp( port );
if( ! soc )
 exit( 0 );

username = "root";
password = "system";

recv1 = recv( socket:soc, length:2048, timeout:10 );

if( "prompt for assistance" >< recv1 && "Username>" >< recv1 ) {
  send( socket:soc, data:username + '\r\n' );
  recv2 = recv( socket:soc, length:2048, timeout:10 );
  if( recv2 =~ "Local_.+>" ) {
    send( socket:soc, data:'set privileged\r\n' );
    recv3 = recv( socket:soc, length:2048, timeout:10 );
    if ( "Password>" >< recv3 ) {
      send( socket:soc, data:'system\r\n\r\n' );
      recv4 = recv( socket:soc, length:2048, timeout:10 );
      close(soc);
      if ( recv4 =~ "Local_.+>>" ) { # The >> indicates the root shell
        vuln = TRUE;
        set_kb_item(name:"lantronix_device/telnet/" + port + "/full_access", value:TRUE );
      }
    }
  }
}

if( soc )
  close( soc );

if( vuln ) {
  report = "It was possible to gain unrestricted telnet access with username '" + username + "' and password '" + password + "'.";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
