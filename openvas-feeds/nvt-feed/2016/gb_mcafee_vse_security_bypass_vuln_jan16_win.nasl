# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:virusscan_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806964");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-8577");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-01-18 14:28:24 +0530 (Mon, 18 Jan 2016)");
  script_name("McAfee VirusScan Enterprise Security Bypass Vulnerability (Jan 2016) - Windows");

  script_tag(name:"summary", value:"McAfee VirusScan Enterprise is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as buffer overflow
  protection feature allocates memory with read, write, execute permissions at
  predictable addresses 32-bit platforms when protecting another application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the DEP and ASLR protection mechanisms via unspecified vectors.");

  script_tag(name:"affected", value:"McAfee VirusScan Enterprise versions before
  8.8 Patch 6 on Windows 32-bit platforms.");

  script_tag(name:"solution", value:"Upgrade to McAfee VirusScan Enterprise
  version 8.8 Patch 6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10142");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78810");
  script_xref(name:"URL", value:"http://blog.ensilo.com/the-av-vulnerability-that-bypasses-mitigations");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");

  script_xref(name:"URL", value:"http://www.mcafee.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x64" >< os_arch){
  exit(0);
}

if(!mcafVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:mcafVer, test_version:"8.8.0.1445"))
{
  report = 'Installed version: ' + mcafVer + '\n' +
           'Fixed version:     ' + "8.8 patch 6 (8.8.0.1445)" + '\n';
  security_message(data:report);
  exit(0);
}

exit(99);