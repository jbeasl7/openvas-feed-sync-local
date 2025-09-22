# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piriform:ccleaner_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811780");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-09-19 13:28:32 +0530 (Tue, 19 Sep 2017)");
  script_name("CCleaner Cloud 'CCleaner.exe' Backdoor Trojan Vulnerability - Windows");

  script_tag(name:"summary", value:"CCleaner Cloud agent is prone to backdoor trojan installation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unauthorized
  modification of the 'CCleaner.exe' binary resulted in an insertion of a two-stage
  backdoor.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to take complete control of system and run code on affected system.");

  script_tag(name:"affected", value:"CCleaner Cloud Agent version 1.07.3191");

  script_tag(name:"solution", value:"Upgrade to CCleaner Cloud version
  1.7.0.3214 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html");
  script_xref(name:"URL", value:"http://www.piriform.com/news/blog/2017/9/18/security-notification-for-ccleaner-v5336162-and-ccleaner-cloud-v1073191-for-32-bit-windows-users");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ccleaner_cloud_agent_detect_win.nasl");
  script_mandatory_keys("CCleaner/Cloud/Win/Ver");
  script_xref(name:"URL", value:"https://www.piriform.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");

## Only 32-bit platform is affected
if((!os_arch) || ("x86" >!< os_arch)){
  exit(0);
}

if(!ccVer = get_app_version(cpe:CPE)){
  exit(0);
}

## 1.07.3191 = 1.7.0.3191
if(ccVer == "1.7.0.3191")
{
  report = report_fixed_ver(installed_version:ccVer, fixed_version:"1.7.0.3214");
  security_message(data:report);
  exit(0);
}
exit(0);
