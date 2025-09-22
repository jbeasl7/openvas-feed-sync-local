# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809006");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2016-2542");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");
  script_tag(name:"creation_date", value:"2016-08-19 19:16:31 +0530 (Fri, 19 Aug 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Flexera InstallShield Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"Flexera InstallShield is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an untrusted search path
  vulnerability in Flexera InstallShield.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to gain privileges via a Trojan horse DLL in the current working
  directory of a setup-launcher executable file.");

  script_tag(name:"affected", value:"Flexera InstallShield through 2015 SP1.");

  script_tag(name:"solution", value:"Apply the patch from the link mentioned in
  reference.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://flexeracommunity.force.com/customer/articles/INFO/Best-Practices-to-Avoid-Windows-Setup-Launcher-Executable-Issues");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84213");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_flexera_installshield_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Flexera/InstallShield/Win/Ver");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

cpe_list = make_list("cpe:/a:flexerasoftware:installshield_2015", "cpe:/a:flexerasoftware:installshield_2014", "cpe:/a:flexerasoftware:installshield_2013");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

checkFile = "Redist\0409\i386\dotnetfx.exe";
sysVer = fetch_file_version(sysPath:path, file_name:checkFile);
if(!sysVer)
  exit(0);

if(vers =~ "^22\.") {
  minRequireVer = "22.0.0.360";
  checkRange = "22.x less than " + minRequireVer;
} else if(vers =~ "^21\.") {
  minRequireVer = "21.0.0.350";
  checkRange = "21.x less than " + minRequireVer;
} else {
  minRequireVer = "20.0.0.530";
  checkRange = "20.x less than " + minRequireVer;
}

if(version_is_less(version:sysVer, test_version:minRequireVer)) {
  report = report_fixed_ver(file_checked:path + "\" + checkFile, installed_version:sysVer, vulnerable_range:checkRange, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
