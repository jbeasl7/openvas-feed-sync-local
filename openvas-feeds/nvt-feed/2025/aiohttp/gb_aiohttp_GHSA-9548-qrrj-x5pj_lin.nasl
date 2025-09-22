# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aio-libs_project:aiohttp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133012");
  script_version("2025-08-15T15:42:26+0000");
  script_cve_id("CVE-2025-53643");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-07-18 07:54:22 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-14 20:40:05 +0000 (Thu, 14 Aug 2025)");
  script_name("aiohttp < 3.12.14 HTTP Request Smuggling Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_aiohttp_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("aio-libs_project/aiohttp/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-9548-qrrj-x5pj");

  script_tag(name:"summary", value:"aiohttp is prone to an HTTP request smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Python parser is vulnerable to a request smuggling
  vulnerability due to not parsing trailer sections of an HTTP request. If a pure Python version
  of aiohttp is installed (i.e. without the usual C extensions) or AIOHTTP_NO_EXTENSIONS is
  enabled, then an attacker may be able to execute a request smuggling attack to bypass certain
  firewalls or proxy protections.");

  script_tag(name:"affected", value:"aiohttp versions prior to 3.12.14.");

  script_tag(name:"solution", value:"Update to version 3.12.14 or later.");

  # nb: No major Linux distributions seems to have backport coverage. We're still using a low QoD
  # here as on Linux the llhttp lib is most likely updated separately...
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
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

if( version_is_less( version:version, test_version:"3.12.14" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.12.14", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
