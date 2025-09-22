# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aio-libs_project:aiohttp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114544");
  script_version("2024-05-03T15:38:41+0000");
  script_cve_id("CVE-2024-27306", "CVE-2024-30251");
  script_tag(name:"last_modification", value:"2024-05-03 15:38:41 +0000 (Fri, 03 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-03 09:54:22 +0000 (Fri, 03 May 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("aiohttp < 3.9.4 Multiple Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_aiohttp_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("aio-libs_project/aiohttp/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5m98-qgg9-wh84");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/05/02/4");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-7gpw-8wmc-pm8g");

  script_tag(name:"summary", value:"aiohttp is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-27306: Cross-site scripting (XSS) on index pages for static file handling

  - CVE-2024-30251: Denial of service (DoS) when trying to parse malformed POST requests");

  script_tag(name:"affected", value:"aiohttp versions prior to 3.9.4.");

  script_tag(name:"solution", value:"Update to version 3.9.4 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

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

if( version_is_less( version:version, test_version:"3.9.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.9.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
