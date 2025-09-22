# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mahara:mahara";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900382");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-2170");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara XSS Vulnerability (Jun 2009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mahara_http_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unknown attack vector can be exploited by injecting
  arbitrary web script or HTML code into the affected application.");

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to conduct a
  cross-site scripting attack.");

  script_tag(name:"affected", value:"Mahara version 1.0 prior to 1.0.12 and 1.1 prior to 1.1.5.");

  script_tag(name:"solution", value:"Update to version 1.1.5, 1.0.12 or later.");

  script_xref(name:"URL", value:"http://mahara.org/interaction/forum/topic.php?id=752");

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

if (version_in_range(version: version, test_version: "1.0", test_version2: "1.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1", test_version2: "1.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
