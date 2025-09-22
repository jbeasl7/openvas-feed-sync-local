# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131008");
  script_version("2024-08-22T05:05:50+0000");
  script_tag(name:"last_modification", value:"2024-08-22 05:05:50 +0000 (Thu, 22 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 08:00:39 +0000 (Tue, 20 Aug 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-20 16:10:30 +0000 (Tue, 20 Aug 2024)");

  script_cve_id("CVE-2024-43400");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 1.1.2 < 14.10.21, 15.0 < 15.5.5, 15.6 < 15.10.6 XSS Vulnerability (GHSA-wcg9-pgqv-xm5v)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Is it possible for a user without Script or Programming rights
  to craft a URL pointing to a page with arbitrary JavaScript. This requires social engineer to
  trick a user to follow the URL.");

  script_tag(name:"affected", value:"XWiki version 1.1.2 prior to 14.10.21, 15.0 prior to 15.5.5
  and 15.6 prior to 15.10.6.");

  script_tag(name:"solution", value:"Update to version 14.10.21, 15.5.5, 15.10.6 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-wcg9-pgqv-xm5v");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"1.1.2", test_version_up:"14.10.21" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.21", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0", test_version_up:"15.5.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.5.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.6", test_version_up:"15.10.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.10.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
