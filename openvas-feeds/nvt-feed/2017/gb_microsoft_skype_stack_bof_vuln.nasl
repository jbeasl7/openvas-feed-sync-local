# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:skype:skype";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811521");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-9948");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-05 17:01:00 +0000 (Wed, 05 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-07-13 11:45:57 +0530 (Thu, 13 Jul 2017)");
  script_name("Microsoft Skype 'MSFTEDIT.DLL' Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Microsoft Skype is prone to a local buffer-overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error located in
  the 'clipboard format' function of the skype software. Attackers are able to
  use a remote computer system with shared clipboard to the cache to provoke a
  stack buffer overflow on transmit to skype. The issue affects the 'MSFTEDIT.DLL'
  dynamic link library.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow attackers to crash the software with one request to overwrite the
  eip register of the active software process. Thus allows local or remote
  attackers to execute own codes on the affected and connected computer systems via
  skype software.");

  script_tag(name:"affected", value:"Microsoft Skype versions 7.2, 7.35.103, 7.36.0.101 and 7.36.0.150.");

  script_tag(name:"solution", value:"Upgrade to Skype version 7.37 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.vulnerability-lab.com/get_content.php?id=2071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99281");
  script_xref(name:"URL", value:"https://www.vulnerability-db.com/?q=articles/2017/05/28/stack-buffer-overflow-zero-day-vulnerability-uncovered-microsoft-skype-v72-v735");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_skype_detect_win.nasl");
  script_mandatory_keys("Skype/Win/Ver");
  script_xref(name:"URL", value:"https://www.skype.com/en");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!skypeVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(skypeVer == "7.2" || skypeVer == "7.35.103" ||
   skypeVer == "7.36.0.101" || skypeVer == "7.36.0.150")
{
  report = report_fixed_ver(installed_version:skypeVer, fixed_version:"7.37");
  security_message(data:report);
  exit(0);
}
