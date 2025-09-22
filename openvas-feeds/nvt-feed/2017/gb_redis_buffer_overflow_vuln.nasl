# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113011");
  script_version("2024-03-04T05:10:24+0000");
  script_tag(name:"last_modification", value:"2024-03-04 05:10:24 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-10-10 14:58:31 +0200 (Tue, 10 Oct 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-28 02:15:00 +0000 (Fri, 28 Aug 2020)");

  # There exists a backport of the vulnerable version for Debian Stretch
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-15047");

  script_name("Redis <= 4.0.2 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the host.");

  script_tag(name:"insight", value:"The clusterLoadConfig function within /redis/src/cluster.c
  allows for a buffer overflow vulnerability leading from an array index being set from
  user-controllable input.");

  script_tag(name:"impact", value:"A successful exploitation would allow the attacker to corrupt the
  host's memory or even execute arbitrary commands on the host.");

  script_tag(name:"affected", value:"Redis version 4.0.2 and prior.");

  script_tag(name:"solution", value:"Update to version 4.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/antirez/redis/issues/4278");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_is_less_equal( version: version, test_version: "4.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.3" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
