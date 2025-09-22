# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:memcached:memcached";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901103");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2010-1152");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Memcached < 1.4.3 DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_memcached_detect.nasl", "gb_memcached_detect_udp.nasl");
  script_mandatory_keys("memcached/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39306");
  script_xref(name:"URL", value:"http://code.google.com/p/memcached/issues/detail?id=102");

  script_tag(name:"summary", value:"Memcached is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause a DoS.");

  script_tag(name:"affected", value:"Memcached 1.4.2 and prior.");

  script_tag(name:"insight", value:"The flaw is due to error in try_read_command() function that
  allows attacker to temporarily hang or potentially crash the server by sending an overly large
  number of bytes.");

  script_tag(name:"solution", value:"Update to version 1.4.3 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

vers = infos["version"];
proto = infos["proto"];

if( version_is_less( version:vers, test_version:"1.4.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.3" );
  security_message( port:port, proto:proto, data:report );
  exit( 0 );
}

exit( 99 );