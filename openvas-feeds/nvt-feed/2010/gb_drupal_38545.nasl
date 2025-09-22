# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100523");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-09 22:32:06 +0100 (Tue, 09 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Drupal 5.x < 5.22 / 6.x < 6.16 Multiple Vulnerabilities (DRUPAL-SA-CORE-2010-001)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38545");
  script_xref(name:"URL", value:"http://drupal.org/node/731710");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_mandatory_keys("drupal/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities, including cross-site
  scripting issues, a phishing issue, and a security-bypass issue.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary code in the
  browser of an unsuspecting user in the context of the affected site, steal cookie-based authentication
  credentials, bypass security restrictions, or perform other attacks.");

  script_tag(name:"affected", value:"Drupal 5.x prior to 5.22 Drupal 6.x prior to 6.16.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"5", test_version2:"5.21") ||
   version_in_range(version:version, test_version:"6", test_version2:"6.15")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.22/6.16", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);