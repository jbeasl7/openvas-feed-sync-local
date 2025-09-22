# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14258");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2004-2255");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 1.3.12 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"The remote web server contains a PHP script that permits
  information disclosure of local files.

  The version of phpMyFAQ on the remote host contains a flaw that may lead to an unauthorized
  information disclosure. The problem is that user input passed to the 'action' parameter is not
  properly verified before being used to include files, which could allow a remote attacker to view
  any accessible file on the system, resulting in a loss of confidentiality.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 1.3.13.");

  script_tag(name:"solution", value:"Update to version 1.3.13 or later.");

  script_xref(name:"URL", value:"http://security.e-matters.de/advisories/052004.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10374");
  script_xref(name:"URL", value:"http://www.phpmyfaq.de/advisory_2004-05-18.php");
  script_xref(name:"OSVDB", value:"6300");

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

if (version_is_less(version: version, test_version: "1.3.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
