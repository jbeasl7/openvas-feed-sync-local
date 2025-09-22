# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105291");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-06-05 15:48:46 +0200 (Fri, 05 Jun 2015)");
  script_name("Redis Server No Password (TCP)");

  # nb: No attacking request (just using previously gathered info) so no ACT_ATTACK
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login...
  script_dependencies("gb_redis_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("redis/no_password");
  script_require_ports("Services/redis", 6379);
  script_exclude_keys("keys/islocalhost", "keys/is_private_lan");

  script_tag(name:"summary", value:"The remote Redis server is not protected with a password.");

  script_tag(name:"vuldetect", value:"Evaluates if the remote Redis server is protected by a
  password.

  Notes:

  - No scan result is expected if localhost (127.0.0.1) was scanned (self scanning)

  - If the scanned network is e.g. a private LAN which contains systems not accessible to the public
  (access restricted) and it is accepted that the target host is accessible without a password
  please set the 'Network type' configuration of the following VT to 'Private LAN':

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"It was possible to login without a password.");

  script_tag(name:"solution", value:"Set password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

# nb: No point in reporting on self scans via 127.0.0.1 as services are often just bound to just
# 127.0.0.1 and thus not accessible externally...
if( islocalhost() )
  exit( 0 );

include("host_details.inc");
include("network_func.inc");

# nb: This might be acceptable from user side if the system is located within a restricted LAN so
# allow this case via the configuration within global_settings.nasl.
if( is_private_lan() )
  exit( 0 );

if( ! port = get_app_port( cpe:CPE, service:"redis" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) ) # nb: To have a reference to the Detection-VT
  exit( 0 );

if( ! get_kb_item( "redis/" + port + "/no_password" ) )
  exit( 99 );

security_message( port:port );
exit( 0 );
