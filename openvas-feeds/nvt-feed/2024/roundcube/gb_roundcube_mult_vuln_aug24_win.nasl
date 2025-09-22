# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:roundcube:webmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114736");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2024-08-05 14:35:26 +0000 (Mon, 05 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-06 21:50:47 +0000 (Fri, 06 Sep 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-42008", "CVE-2024-42009", "CVE-2024-42010");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail < 1.5.8, 1.6.x < 1.6.8 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("roundcube/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-42008: Cross-site scripting (XSS) vulnerability in serving of attachments other than
  HTML or SVG

  - CVE-2024-42009: XSS vulnerability in post-processing of sanitized HTML content

  - CVE-2024-42010: Information leak (access to remote content) via insufficient CSS filtering");

  script_tag(name:"affected", value:"Roundcube Webmail versions prior to 1.5.8 and 1.6.x
  prior to 1.6.8.");

  script_tag(name:"solution", value:"Update to version 1.5.8, 1.6.8 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2024/08/04/security-updates-1.6.8-and-1.5.8");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/releases/tag/1.6.8");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/releases/tag/1.5.8");
  script_xref(name:"URL", value:"https://github.com/0xbassiouny1337/CVE-2024-42009");
  script_xref(name:"URL", value:"https://cert.pl/en/posts/2025/06/unc1151-campaign-roundcube/");

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

if( version_is_less( version:version, test_version:"1.5.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.5.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.6", test_version_up:"1.6.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.6.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
