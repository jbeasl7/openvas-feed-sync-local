# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108759");
  script_version("2025-05-28T05:40:15+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-05-28 05:40:15 +0000 (Wed, 28 May 2025)");
  script_tag(name:"creation_date", value:"2020-04-24 11:59:06 +0000 (Fri, 24 Apr 2020)");
  script_name("Huawei VRP Default Credentials (FTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/huawei/vrp/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1000060368/25506195/understanding-the-list-of-default-user-names-and-passwords");
  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1000079719/1b8f7bdb/logging-in-to-an-ar-router-through-a-web-system");

  script_tag(name:"summary", value:"The remote Huawei Versatile Routing Platform (VRP) device is
  using known default credentials for the FTP login.");

  script_tag(name:"vuldetect", value:"Tries to login via FTP using known default credentials.");

  script_tag(name:"insight", value:"The remote Huawei Versatile Routing Platform (VRP) device is
  lacking a proper password configuration, which makes critical information and actions accessible
  for people with knowledge of the default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the default password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

creds = make_list(
  "admin:admin@huawei.com",
  "admin:admin",
  "admin:Admin@huawei",
  "admin:Admin@123",
  "root:admin",
  "super:sp-admin"
);

report = 'It was possible to login to the remote Huawei VRP device via FTP with the following known credentials:';

port = ftp_get_port( default:21 );

banner = ftp_get_banner( port:port );
if( ! banner || banner != "220 FTP service ready." )
  exit( 0 );

if( ftp_broken_random_login( port:port ) )
  exit( 0 );

foreach cred( creds ) {

  if( ! soc = ftp_open_socket( port:port ) )
    continue;

  split = split( cred, sep:":", keep:FALSE );
  if( max_index( split ) != 2 ) {
    ftp_close( socket:soc );
    continue;
  }

  username = split[0];
  password = split[1];

  login = ftp_authenticate( socket:soc, user:username, pass:password, skip_banner:TRUE );
  ftp_close( socket:soc );

  if( login ) {
    vuln = TRUE;
    report += '\n\nUsername: "' + username  + '", Password: "' + password + '"';
  }
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
