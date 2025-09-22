# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aio-libs_project:aiohttp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126893");
  script_version("2025-08-20T05:40:05+0000");
  script_cve_id("CVE-2024-42367");
  script_tag(name:"last_modification", value:"2025-08-20 05:40:05 +0000 (Wed, 20 Aug 2025)");
  script_tag(name:"creation_date", value:"2024-08-13 12:14:56 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-19 15:12:45 +0000 (Tue, 19 Aug 2025)");

  script_name("aiohttp < 3.10.2 Path Traversal Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_aiohttp_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("aio-libs_project/aiohttp/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-jwhx-xcg6-8xhj");

  script_tag(name:"summary", value:"aiohttp is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Static routes containing files with compressed variants (.gz or
  .br extensions) are vulnerable to path traversal outside the root directory if those variants,
  are symbolic links.");

  script_tag(name:"affected", value:"aiohttp versions prior to 3.10.2.");

  script_tag(name:"solution", value:"Update to version 3.10.2 or later.");

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

if( version_is_less( version:version, test_version:"3.10.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.10.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );