# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100932");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2010-12-02 19:42:22 +0100 (Thu, 02 Dec 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-4260");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV < 0.96.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_clamav_consolidation.nasl");
  script_mandatory_keys("clamav/detected");

  script_tag(name:"summary", value:"ClamAV is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers may exploit these issues to cause denial-of-service
  conditions or potentially execute arbitrary code in the context of the application.");

  script_tag(name:"affected", value:"ClamAV prior to version 0.96.5.");

  script_tag(name:"solution", value:"Update to version 0.96.5 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45152");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=1f3db7f074995bd4e1d0183b2db8b1c472d2f41b");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=019f1955194360600ecf0644959ceca6734c2d7b");
  script_xref(name:"URL", value:"http://freshmeat.net/projects/clamav/releases/325193");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "0.96.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.96.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
