# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16162");
  script_version("2025-03-27T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2005-0378");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde 3.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("horde_http_detect.nasl");
  script_mandatory_keys("horde/detected");

  script_tag(name:"summary", value:"Horde is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Through specially crafted GET requests to the remote host, an
  attacker can cause a third party user to unknowingly run arbitrary Javascript code.");

  script_tag(name:"solution", value:"Update to version 3.0.1 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/35724/H2005-01.txt.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12255");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"3.0", test_version_up:"3.0.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.0.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
