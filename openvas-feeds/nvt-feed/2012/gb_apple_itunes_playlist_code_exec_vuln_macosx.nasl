# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802863");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2012-0677");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-06-12 15:25:52 +0530 (Tue, 12 Jun 2012)");
  script_name("Apple iTunes '.m3u' Playlist Code Execution Vulnerability - Mac OS X");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5318");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49489");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027142");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Jun/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_itunes_detect_macosx.nasl");
  script_mandatory_keys("Apple/iTunes/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Apple iTunes version prior to 10.6.3 on Mac OS X.");

  script_tag(name:"insight", value:"Apple iTunes fails to handle '.m3u' playlist, allowing to cause a heap
  overflow and execute arbitrary code on the target system.");

  script_tag(name:"solution", value:"Upgrade to Apple Apple iTunes version 10.6.3 or later.");

  script_tag(name:"summary", value:"Apple iTunes is prone to code execution vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"10.6.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.6.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
