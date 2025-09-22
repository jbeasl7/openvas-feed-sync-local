# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902760");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-11-22 17:51:52 +0530 (Tue, 22 Nov 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2011-3627");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV < 0.97.3 Recursion Level Handling DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the way the bytecode engine handled
  recursion level when scanning an unpacked file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial
  of service (crash) via vectors related to recursion level.");

  script_tag(name:"affected", value:"ClamAV before version 0.97.3.");

  script_tag(name:"solution", value:"Update to version 0.97.3 or later.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/USN-1258-1/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50183");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=746984");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=3d664817f6ef833a17414a4ecea42004c35cc42f");

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

if (version_is_less(version: version, test_version: "0.97.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.97.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
