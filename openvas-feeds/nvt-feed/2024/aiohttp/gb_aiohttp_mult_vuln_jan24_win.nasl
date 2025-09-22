# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aio-libs_project:aiohttp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114546");
  script_version("2024-05-03T15:38:41+0000");
  script_cve_id("CVE-2024-23334", "CVE-2024-23829");
  script_tag(name:"last_modification", value:"2024-05-03 15:38:41 +0000 (Fri, 03 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-03 09:54:22 +0000 (Fri, 03 May 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 18:44:40 +0000 (Mon, 05 Feb 2024)");
  script_name("aiohttp < 3.9.2 Multiple Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_aiohttp_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("aio-libs_project/aiohttp/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-8qpw-xqxj-h4r2");

  script_tag(name:"summary", value:"aiohttp is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-23334: Directory traversal vulnerability

  - CVE-2024-23829: HTTP parser still overly lenient about separators");

  # nb:
  # - Advisory GHSA-5h86-8mv2-jq9f says > 1.0.5 as affected versions but as this is quite aged this
  #   VT hasn't been split into two for simplicity
  # - Advisory GHSA-8qpw-xqxj-h4r2 says "Affected versions < 3.9.1" and "Patched versions 3.9.2"
  #   which is contradictory but as the CVE-2024-23829 description says "Version 3.9.2 fixes this
  #   vulnerability it is assumed that the "Patched versions" string is correct
  script_tag(name:"affected", value:"aiohttp versions prior to 3.9.2.");

  script_tag(name:"solution", value:"Update to version 3.9.2 or later.");

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

if( version_is_less( version:version, test_version:"3.9.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.9.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
