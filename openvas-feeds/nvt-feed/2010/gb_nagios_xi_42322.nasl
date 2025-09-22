# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios_xi";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100753");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-08-10 14:55:08 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios XI < 2009R1.2C Multiple CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_nagios_xi_http_detect.nasl");
  script_mandatory_keys("nagios/nagios_xi/detected");

  script_tag(name:"summary", value:"Nagios XI is prone to multiple cross-site request forgery (CSRF)
  vulnerabilities because the application fails to properly validate HTTP requests.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Successful exploit requires that the 'nagiosadmin' be logged into
  the web interface.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to gain unauthorized access to
  the affected application and perform certain administrative actions.");

  script_tag(name:"affected", value:"Nagios XI 2009R1.2B is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution", value:"Reportedly, these issues have been fixed in Nagios XI 2009R1.2C.
  Please see the references for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42322");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/512967");

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
if (version_in_range_exclusive(version: version, test_version_lo: "2009", test_version_up: "2009r1.2c")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2009R1.2C", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
