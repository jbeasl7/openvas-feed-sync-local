# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mahara:mahara";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100334");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2009-11-04 12:36:10 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2009-3298", "CVE-2009-3299");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara Multiple Vulnerabilities (Nov 2009)");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_mahara_http_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to a security bypass and cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to reset the application's
  administrator password or to execute arbitrary script code in the browser of an unsuspecting user
  in the context of the affected site.");

  script_tag(name:"affected", value:"Mahara prior to version 1.0.13 and 1.1 prior to 1.1.7.");

  script_tag(name:"solution", value:"Update to version 1.0.13, 1.1.7 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36892");
  script_xref(name:"URL", value:"http://wiki.mahara.org/Release_Notes/1.1.7");
  script_xref(name:"URL", value:"http://mahara.org/interaction/forum/topic.php?id=1169");
  script_xref(name:"URL", value:"http://mahara.org/interaction/forum/topic.php?id=1170");

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

if (version_in_range(version: version, test_version: "1.0", test_version2: "1.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1", test_version2: "1.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
