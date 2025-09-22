# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105290");
  script_cve_id("CVE-2015-4335");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2025-01-21T05:37:33+0000");

  script_name("Redis < 2.8.21, 3.x < 3.0.2 EVAL Lua Sandbox Escape Vulnerability");

  script_xref(name:"URL", value:"http://benmmurphy.github.io/blog/2015/06/04/redis-eval-lua-sandbox-escape/");

  script_tag(name:"impact", value:"Successfully attack may allow the attacker to execute code in the
  context of the application");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"It is possible to break out of the Lua sandbox in Redis and
  execute arbitrary code.");

  script_tag(name:"affected", value:"Redis versions prior to 2.8.21 and 3.x prior to 3.0.2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-06-05 16:01:37 +0200 (Fri, 05 Jun 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.1" ) ||
    version_is_less_equal( version:vers, test_version:"2.8.20" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.2 / 2.8.21" );
  security_message( port:port, data:report );
  exit (0 );
}

exit( 99 );
