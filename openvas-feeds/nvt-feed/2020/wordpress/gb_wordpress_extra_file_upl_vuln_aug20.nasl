# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112799");
  script_version("2023-09-29T05:05:51+0000");
  script_tag(name:"last_modification", value:"2023-09-29 05:05:51 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2020-08-06 12:54:00 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-12 20:41:00 +0000 (Tue, 12 Jan 2021)");

  script_cve_id("CVE-2020-35945");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elegant Themes Extra Theme 2.0 <= 4.5.2 Authenticated Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_themes_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/extra/detected");

  script_tag(name:"summary", value:"The WordPress theme Extra by Elegant Themes is prone to an authenticated arbitrary file upload vulnerability.");

  script_tag(name:"insight", value:"The theme uses a client-side file type verification check, but it was missing a server-side verification check.
  This flaw made it possible for authenticated attackers to easily bypass the JavaScript client-side check and upload
  malicious PHP files to a targeted website.

  An attacker could easily use a malicious file uploaded via this method to completely take over a site.");

  script_tag(name:"impact", value:"This flaw gave authenticated attackers, with contributor-level or above capabilities,
  the ability to upload arbitrary files, including PHP files, and achieve remote code execution on a vulnerable site's server.");

  script_tag(name:"affected", value:"WordPress Extra theme by Elegant Themes versions 2.0 through 4.5.2.");

  script_tag(name:"solution", value:"Update to version 4.5.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/08/critical-vulnerability-exposes-over-700000-sites-using-divi-extra-and-divi-builder/");

  exit(0);
}

CPE = "cpe:/a:elegantthemes:extra";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.0", test_version2: "4.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.5.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
