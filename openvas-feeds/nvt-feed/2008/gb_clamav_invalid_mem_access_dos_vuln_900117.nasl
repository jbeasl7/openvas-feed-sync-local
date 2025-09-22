# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900117");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2008-09-05 16:50:44 +0200 (Fri, 05 Sep 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2008-1389");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV < 0.94 Invalid Memory Access DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_consolidation.nasl");
  script_mandatory_keys("clamav/detected");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an invalid memory access in chmunpack.c
  file, when processing a malformed CHM file.");

  script_tag(name:"impact", value:"Successful remote exploitation will allow attackers to cause
  the application to crash.");

  script_tag(name:"affected", value:"ClamAV prior to version 0.94.");

  script_tag(name:"solution", value:"Update to version 0.94 or later.");

  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2484");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30994");
  script_xref(name:"URL", value:"http://svn.clamav.net/svn/clamav-devel/trunk/ChangeLog");

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

if (version_is_less(version: version, test_version: "0.94")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.94", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
