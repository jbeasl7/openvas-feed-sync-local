# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios_xi";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100811");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Nagios XI 'users.php' Multiple XSS Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_nagios_xi_http_detect.nasl");
  script_mandatory_keys("nagios/nagios_xi/detected");

  script_tag(name:"summary", value:"Nagios XI is prone to multiple cross-site scripting (XSS)
  vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow the
  attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Nagios XI 2009R1.3B is vulnerable, prior versions may also be
  affected.");

  script_tag(name:"solution", value:"Update to version 2009R1.3C or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43294");
  script_xref(name:"URL", value:"https://web.archive.org/web/20100923132409/http://secunia.com/secunia_research/2010-115/");
  script_xref(name:"URL", value:"http://assets.nagios.com/downloads/nagiosxi/CHANGES.TXT");

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

# nb: About the versions:
# - 2009 was the first one up to 2014
# - After 2014 version 5.x started
# - We can't use version_is_less() here as we would cause a false positive for 5.x versions
if (version_in_range_exclusive(version: version, test_version_lo: "2009", test_version_up: "2009r1.3c")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2009R1.3C", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
