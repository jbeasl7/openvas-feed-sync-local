# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:quagga:quagga";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105552");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-02-16 17:31:57 +0100 (Tue, 16 Feb 2016)");

  script_name("Quagga Server No Password (TCP)");

  # nb: No attacking request (just "grabbing" a login banner) so no ACT_ATTACK
  script_category(ACT_GATHER_INFO);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login...
  script_dependencies("gb_quagga_remote_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/quagga", 2602);
  script_mandatory_keys("quagga/installed");
  script_exclude_keys("keys/is_private_lan");

  script_tag(name:"summary", value:"The remote Quagga server is not protected with a password.");

  script_tag(name:"vuldetect", value:"Connects to the remote Quagga server and checks if a password
  is needed.

  Note:

  If the scanned network is e.g. a private LAN which contains systems not accessible to the public
  (access restricted) and it is accepted that the target host is accessible without a password
  please set the 'Network type' configuration of the following VT to 'Private LAN':

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"insight", value:"It was possible to login without a password.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Set a password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("network_func.inc");

# nb: This might be acceptable from user side if the system is located within a restricted LAN so
# allow this case via the configuration within global_settings.nasl.
if( is_private_lan() )
  exit( 0 );

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

recv = recv( socket:soc, length:512 );

if( "Password:" >< recv ) {
  close( soc );
  exit( 99 );
}

send( socket:soc, data:'?\r\n' );

recv = recv( socket:soc, length:512 );
close( soc );

if( "echo" >!< recv || "enable" >!< recv || "terminal" >!< recv )
  exit( 0 );

report = 'It was possible to access the remote Quagga without a password.\n\nData received:\n\n' + recv;
security_message( port:port, data:report );

exit( 0 );
