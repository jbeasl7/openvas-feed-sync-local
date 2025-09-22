# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flexerasoftware:installanywhere";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809019");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2016-4560");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:18:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-08-29 13:05:30 +0530 (Mon, 29 Aug 2016)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_name("Flexera InstallAnywhere Privilege Escalation Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Flexera InstallAnywhere is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an untrusted search path
  vulnerability in Flexera InstallAnywhere.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to gain privileges via a Trojan horse DLL in the current working
  directory of a setup-launcher executable file.");

  script_tag(name:"affected", value:"Flexera InstallAnywhere all versions on Mac OS X.");

  script_tag(name:"solution", value:"Apply the hotfix from the link mentioned in
  reference.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://flexeracommunity.force.com/customer/articles/INFO/Best-Practices-to-Avoid-Windows-Setup-Launcher-Executable-Issues");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90979");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_flexera_installanywhere_detect_macosx.nasl");
  script_mandatory_keys("InstallAnywhere/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.flexerasoftware.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!installVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:installVer, test_version:"17.0"))
{
  report = report_fixed_ver(installed_version:installVer, fixed_version:"Apply the hotfix");
  security_message(data:report);
  exit(0);
}
