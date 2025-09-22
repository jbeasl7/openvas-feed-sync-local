# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812909");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-0850", "CVE-2018-0852");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-02-14 10:54:29 +0530 (Wed, 14 Feb 2018)");
  script_name("Microsoft Outlook 2007 Service Pack 3 Multiple Vulnerabilities (KB4011200)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4011200");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Microsoft Outlook when the software fails to properly handle
    objects in memory.

  - When Microsoft Outlook initiates processing of incoming messages without
    sufficient validation of the formatting of the messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to run arbitrary code in the
  context of the current user and force Outlook to load a local or remote message
  store (over SMB).");

  script_tag(name:"affected", value:"Microsoft Outlook 2007 Service Pack 3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011200");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102871");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Outlook/Version");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

outlookVer = get_kb_item("SMB/Office/Outlook/Version");

if(!outlookVer || outlookVer !~ "^12\."){
  exit(0);
}

outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OUTLOOK.EXE", item:"Path");
if(!outlookFile){
  exit(0);
}

outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"outlook.exe");
if(!outlookVer || outlookVer !~ "^12\."){
  exit(0);
}

if(version_is_less(version:outlookVer, test_version:"12.0.6785.5000"))
{
  report = report_fixed_ver(file_checked:outlookFile + "outlook.exe",
           file_version:outlookVer, vulnerable_range:"12.0 - 12.0.6785.4999");
  security_message(data:report);
  exit(0);
}
exit(0);
