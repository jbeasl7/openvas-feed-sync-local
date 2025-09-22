# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805688");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2015-07-23 13:10:57 +0530 (Thu, 23 Jul 2015)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-6501", "CVE-2015-1353");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.6.x < 5.6.8 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Integer overflow vulnerability in PHP's Calendar Extension Conversion functions.

  - Flaw in the cache directory that is due to the program creating files for the cache in a
  predictable manner.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to
  inject WSDL files and have them be used in place of the intended file and unexpected data result
  while using Calendar Extension Conversion functions.");

  script_tag(name:"affected", value:"PHP versions 5.6.x through 5.6.7.");

  script_tag(name:"solution", value:"Update to version 5.6.8 or later.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1009103");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72267");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72530");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1185896");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2015-03/msg00003.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "5.6.0", test_version2: "5.6.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
