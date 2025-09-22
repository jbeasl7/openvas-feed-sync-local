# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:simplemachines:smf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900118");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2008-6971");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Simple Machines Forum (SMF) < 1.1.6 Password Reset Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_http_detect.nasl");
  script_mandatory_keys("smf/detected");

  script_tag(name:"summary", value:"Simple Machines Forum (SMF) is prone to a security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists due to the application generating weak
  validation codes for the password reset functionality which allows for easy validation code
  guessing attack.");

  script_tag(name:"impact", value:"Attackers can guess the validation code and reset the user
  password to the one of their choice.");

  script_tag(name:"affected", value:"SMF versions prior to 1.1.6.");

  script_tag(name:"solution", value:"Update to version 1.1.6 or later.");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6392");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31053");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31750/");
  script_xref(name:"URL", value:"http://www.simplemachines.org/community/index.php?topic=260145.0");

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

if (version_is_less(version: version, test_version: "1.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
