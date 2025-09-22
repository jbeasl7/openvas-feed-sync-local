# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aio-libs_project:aiohttp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114555");
  script_version("2024-05-08T05:05:32+0000");
  script_cve_id("CVE-2023-47627");
  script_tag(name:"last_modification", value:"2024-05-08 05:05:32 +0000 (Wed, 08 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-07 08:55:56 +0000 (Tue, 07 May 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-22 22:40:55 +0000 (Wed, 22 Nov 2023)");
  script_name("aiohttp < 3.8.6 HTTP Request Smuggling Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_aiohttp_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("aio-libs_project/aiohttp/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-gfw2-4jvh-wgfg");

  script_tag(name:"summary", value:"aiohttp is prone to a HTTP request smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The HTTP parser in AIOHTTP has numerous problems with header
  parsing, which could lead to request smuggling. This parser is only used when
  AIOHTTP_NO_EXTENSIONS is enabled (or not using a prebuilt wheel).");

  script_tag(name:"affected", value:"aiohttp versions prior to 3.8.6.");

  script_tag(name:"solution", value:"Update to version 3.8.6 or later.");

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

if( version_is_less( version:version, test_version:"3.8.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.8.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
