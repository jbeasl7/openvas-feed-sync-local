# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14364");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2004-1923", "CVE-2004-1924", "CVE-2004-1925", "CVE-2004-1926",
                "CVE-2004-1927", "CVE-2004-1928");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tiki Wiki CMS Groupware < 1.8.2 Multiple Input Validation Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple vulnerabilities
  in various modules of the application.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"These vulnerabilities may allow a remote attacker to carry out
  various attacks such as path disclosure, cross-site scripting, HTML injection, SQL injection,
  directory traversal, and arbitrary file upload.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware prior to version 1.8.2.");

  script_tag(name:"solution", value:"Update to version 1.8.2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10100");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
