# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817659");
  script_version("2025-08-28T05:39:05+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-1647");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-14 19:28:00 +0000 (Thu, 14 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-13 08:24:09 +0530 (Wed, 13 Jan 2021)");
  script_name("Microsoft Windows Defender Antimalware Platform RCE Vulnerability (Jan 2021)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Security Updates released for Microsoft Windows
  Defender Protection Engine dated 12-01-2021");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host");

  script_tag(name:"insight", value:"The flaw exists while opening a malicious
  document on a system where Microsoft Windows Defender is installed");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows Defender on Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2019

  - Microsoft Windows Server 2016

  - Microsoft Windows 7 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2008 x32

  - Microsoft Windows Server 2008 R2 x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"Run the Windows Update to update the malware
  protection engine to the latest version available. Typically, no action is
  required as the built-in mechanism for the automatic detection and deployment
  of updates will apply the update itself.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1647");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_defender_smb_login_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "microsoft/defender/mpe_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1,win2012:1, win2012R2:1,
                   win10:1, win10x64:1, win2016:1, win2008:3, win2019:1) <= 0){
  exit(0);
}

if(!version = get_kb_item("microsoft/defender/mpe_version"))
  exit(0);

if(version_is_less(version:version, test_version:"1.1.17600.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.1.17600.5");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
