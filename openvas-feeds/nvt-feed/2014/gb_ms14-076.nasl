# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805016");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2014-4078");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-12 13:00:44 +0530 (Wed, 12 Nov 2014)");
  script_name("Microsoft Internet Information Services Security Feature Bypass Vulnerability (2982998)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-076.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error within the
  Microsoft Internet Information Services (IIS) component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services 8.0/8.5 on Microsoft Windows 8 x32/x64 and Microsoft Windows 8.1 x32/x64 Edition.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2982998");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70937");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-076");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_iis_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IIS/Ver");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(!iisVer = get_app_version(cpe:CPE))
  exit(0);

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0)
  exit(0);

sysPath = smb_get_systemroot();
if(!sysPath)
  exit(0);

file = "system32\inetsrv\Iprestr.dll";
checked = sysPath + "\" + file;
dllVer = fetch_file_version(sysPath:sysPath, file_name:file);
if(!dllVer)
  exit(0);

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0) {
  if(version_is_less(version:dllVer, test_version:"8.0.9200.17101") ||
     version_in_range(version:dllVer, test_version:"8.0.9200.20000", test_version2:"8.0.9200.21217")) {
    report = report_fixed_ver(file_checked:checked, file_version:dllVer, vulnerable_range:"< 8.0.9200.17101 / 8.0.9200.20000 - 8.0.9200.21217");
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0) {
  if(version_is_less(version:dllVer, test_version:"8.5.9600.17265")) {
    report = report_fixed_ver(file_checked:checked, file_version:dllVer, vulnerable_range:"< 8.5.9600.17265");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
