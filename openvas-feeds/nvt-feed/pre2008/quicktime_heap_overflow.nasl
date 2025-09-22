# SPDX-FileCopyrightText: 2004 Jeff Adams
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12226");
  script_version("2023-08-03T05:05:16+0000");
  script_cve_id("CVE-2004-0431");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Quicktime player/plug-in Heap overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Jeff Adams");
  script_family("Windows");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"solution", value:"Update to version 6.5.1 or later.");

  script_tag(name:"summary", value:"The remote host is using QuickTime, a popular media player/Plug-in
  which handles many Media files.");

  script_tag(name:"impact", value:"This version has a Heap overflow which may allow an attacker
  to execute arbitrary code on this host, with the rights of the user running QuickTime.");

  script_xref(name:"URL", value:"http://eeye.com/html/Research/Advisories/AD20040502.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10257");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"6.5.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.5.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
