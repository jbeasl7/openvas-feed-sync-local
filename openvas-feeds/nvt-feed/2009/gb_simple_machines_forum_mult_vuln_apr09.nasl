# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:simplemachines:smf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800558");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2008-6657", "CVE-2008-6658", "CVE-2008-6659");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Simple Machines Forum (SMF) 1.x < 1.1.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_http_detect.nasl");
  script_mandatory_keys("smf/detected");

  script_tag(name:"summary", value:"Simple Machines Forum (SMF) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Lack of access control and validation check while performing certain HTTP requests which lets
  the attacker perform certain administrative commands.

  - Lack of validation check for the 'theme_dir' settings before being used which causes arbitrary
  code execution from local resources.

  - Crafted avatars are being allowed for code execution.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute malicious
  arbitrary codes in the context of the SMF web application to gain administrative privileges,
  install malicious components into the forum context or can cause directory traversal attacks
  also.");

  script_tag(name:"affected", value:"SMF versions 1.0 through 1.0.14 and 1.1 through
  1.1.6.");

  script_tag(name:"solution", value:"Update to version to 1.1.7 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32516");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32119");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32139");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6993");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7011");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46343");

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

if (version_in_range(version: version, test_version: "1.0", test_version2: "1.0.14") ||
    version_in_range(version: version, test_version: "1.1", test_version2: "1.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
