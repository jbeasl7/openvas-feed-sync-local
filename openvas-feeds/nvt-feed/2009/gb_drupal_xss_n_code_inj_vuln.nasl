# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800908");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2372", "CVE-2009-2373");
  script_name("Drupal XSS and Code Injection Vulnerability");
  script_xref(name:"URL", value:"http://drupal.org/node/507572");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35548");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35681");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jul/1022497.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_mandatory_keys("drupal/detected");

  script_tag(name:"impact", value:"Attackers can exploit this issue to conduct script insertion attacks and
  inject and execute arbitrary PHP, HTML and script code.");

  script_tag(name:"affected", value:"Drupal version 6.x before 6.13 on all platforms.");

  script_tag(name:"insight", value:"Multiple flaws arise because,

  - The users can modify user signatures after the associated comment format is
  changed to an administrator-controlled input format, which allows remote
  authenticated users to inject arbitrary code via a crafted user signature.

  - When input passed into the unspecified vectors in the Forum module is not
  properly sanitised before being returned to the user.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Drupal 6.13 or later.");

  script_tag(name:"summary", value:"Drupal is prone to Cross Site Scripting and Remote Code Injection vulnerabilities.");
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

if(version_in_range(version:version, test_version:"6.0", test_version2:"6.12")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.13", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);