# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804484");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2014-1347");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2014-09-18 14:45:02 +0530 (Thu, 18 Sep 2014)");


  script_name("Apple iTunes Insecure Permissions Privilege Escalation Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Apple iTunes is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as world-writable permissions
  are set for the /Users and /Users/Shared directories upon reboot");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to manipulate contents in the directories and gain escalated
  privileges.");

  script_tag(name:"affected", value:"Apple iTunes prior to 11.2.1 for Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to iTunes 11.2.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67457");
  script_xref(name:"URL", value:"http://secunia.com/advisories/58444");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/May/99");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126720");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("secpod_itunes_detect_macosx.nasl");
  script_mandatory_keys("Apple/iTunes/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"11.2.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.2.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
