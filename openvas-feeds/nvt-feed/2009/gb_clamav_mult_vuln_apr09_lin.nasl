# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800554");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2008-6680", "CVE-2009-1241", "CVE-2009-1270");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV < 0.95 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ClamAV is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2009-1241: Error in handling specially crafted RAR files which prevents the scanning of
  potentially malicious files.

  - CVE-2009-1270: Error in libclamav/untar.c allows remote attacker to cause an infinite loup
  through a crafted TAR file, which causes clamd and clamscan to hang.

  - CVE-2008-6680: 'libclamav/pe.c' allows remote attackers to cause a denial of service via a
  crafted EXE which triggers a divide-by-zero error.");

  script_tag(name:"impact", value:"Remote attackers may exploit this issue to inject malicious
  files into the system which can bypass the scan engine and may cause denial of service.");

  script_tag(name:"affected", value:"ClamAV prior to version 0.95.");

  script_tag(name:"solution", value:"Update to version 0.95 or later.");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0934");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34344");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34357");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/04/07/6");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/04/clamav-094-and-below-evasion-and-bypass.html");

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

if (version_is_less(version: version, test_version: "0.95")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.95", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
