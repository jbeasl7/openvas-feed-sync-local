# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817356");
  script_version("2024-06-26T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-0648", "CVE-2020-0664", "CVE-2020-0718", "CVE-2020-0761",
                "CVE-2020-0766", "CVE-2020-0782", "CVE-2020-0790", "CVE-2020-0805",
                "CVE-2020-0836", "CVE-2020-0837", "CVE-2020-0838", "CVE-2020-0839",
                "CVE-2020-0856", "CVE-2020-0875", "CVE-2020-0878", "CVE-2020-0886",
                "CVE-2020-0890", "CVE-2020-0904", "CVE-2020-0908", "CVE-2020-0911",
                "CVE-2020-0912", "CVE-2020-0914", "CVE-2020-0921", "CVE-2020-0922",
                "CVE-2020-0928", "CVE-2020-0941", "CVE-2020-0951", "CVE-2020-0989",
                "CVE-2020-0997", "CVE-2020-0998", "CVE-2020-1012", "CVE-2020-1013",
                "CVE-2020-1030", "CVE-2020-1031", "CVE-2020-1033", "CVE-2020-1034",
                "CVE-2020-1038", "CVE-2020-1039", "CVE-2020-1052", "CVE-2020-1053",
                "CVE-2020-1057", "CVE-2020-1074", "CVE-2020-1083", "CVE-2020-1091",
                "CVE-2020-1097", "CVE-2020-1098", "CVE-2020-1115", "CVE-2020-1119",
                "CVE-2020-1122", "CVE-2020-1129", "CVE-2020-1130", "CVE-2020-1133",
                "CVE-2020-1146", "CVE-2020-1152", "CVE-2020-1159", "CVE-2020-1169",
                "CVE-2020-1172", "CVE-2020-1180", "CVE-2020-1228", "CVE-2020-1245",
                "CVE-2020-1250", "CVE-2020-1252", "CVE-2020-1256", "CVE-2020-1285",
                "CVE-2020-1303", "CVE-2020-1308", "CVE-2020-1376", "CVE-2020-1471",
                "CVE-2020-1491", "CVE-2020-1506", "CVE-2020-1507", "CVE-2020-1508",
                "CVE-2020-1532", "CVE-2020-1559", "CVE-2020-1589", "CVE-2020-1590",
                "CVE-2020-1592", "CVE-2020-1593", "CVE-2020-1596", "CVE-2020-1598",
                "CVE-2020-16854", "CVE-2020-16879");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 12:58:00 +0000 (Mon, 28 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-09 09:00:21 +0530 (Wed, 09 Sep 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4571756)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4571756");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to errors,

  - when Microsoft Windows CloudExperienceHost fails to check COM objects.

  - in the way that Microsoft COM for Windows handles objects in memory.

  - when the Windows InstallService improperly handles memory.

  - when the Connected User Experiences and Telemetry Service improperly handles file operations.

  - when the Windows kernel improperly initializes objects in memory.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privileges, conduct DoS condition, bypass
  security restrictions and disclose sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 2004 for 32-bit Systems

  - Microsoft Windows 10 Version 2004 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4571756");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Gdiplus.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.19041.0", test_version2:"10.0.19041.507"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Gdiplus.dll",
                            file_version:fileVer, vulnerable_range:"10.0.19041.0 - 10.0.19041.507");
  security_message(data:report);
  exit(0);
}
exit(99);
