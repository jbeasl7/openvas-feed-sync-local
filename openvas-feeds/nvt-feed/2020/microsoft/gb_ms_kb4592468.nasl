# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817547");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2020-16996", "CVE-2020-17049", "CVE-2020-17092", "CVE-2020-17096",
                "CVE-2020-17097", "CVE-2020-17098", "CVE-2020-17140");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-31 18:15:00 +0000 (Sun, 31 Dec 2023)");
  script_tag(name:"creation_date", value:"2020-12-09 10:24:26 +0530 (Wed, 09 Dec 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4592468)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4592468");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Kerberos Security Feature.

  - An error in the GDI+ component.

  - An error in the SMBv2 component.
  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges and disclose sensitive information.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4592468");
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

fileVer = "";
dllPath = "";
report = "";

if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Localspl.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.2.9200.23221"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Localspl.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.2.9200.23221");
  security_message(data:report);
  exit(0);
}
exit(99);
