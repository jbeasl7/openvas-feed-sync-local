# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817568");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2021-1637", "CVE-2021-1642", "CVE-2021-1645", "CVE-2021-1648",
                "CVE-2021-1649", "CVE-2021-1650", "CVE-2021-1651", "CVE-2021-1652",
                "CVE-2021-1653", "CVE-2021-1654", "CVE-2021-1655", "CVE-2021-1656",
                "CVE-2021-1657", "CVE-2021-1658", "CVE-2021-1659", "CVE-2021-1660",
                "CVE-2021-1661", "CVE-2021-1664", "CVE-2021-1665", "CVE-2021-1666",
                "CVE-2021-1667", "CVE-2021-1668", "CVE-2021-1669", "CVE-2021-1671",
                "CVE-2021-1673", "CVE-2021-1674", "CVE-2021-1676", "CVE-2021-1678",
                "CVE-2021-1679", "CVE-2021-1680", "CVE-2021-1681", "CVE-2021-1683",
                "CVE-2021-1684", "CVE-2021-1685", "CVE-2021-1686", "CVE-2021-1687",
                "CVE-2021-1688", "CVE-2021-1689", "CVE-2021-1690", "CVE-2021-1692",
                "CVE-2021-1693", "CVE-2021-1694", "CVE-2021-1695", "CVE-2021-1696",
                "CVE-2021-1697", "CVE-2021-1699", "CVE-2021-1700", "CVE-2021-1701",
                "CVE-2021-1702", "CVE-2021-1704", "CVE-2021-1705", "CVE-2021-1706",
                "CVE-2021-1708", "CVE-2021-1709", "CVE-2021-1710");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-21 14:40:00 +0000 (Thu, 21 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-13 08:35:03 +0530 (Wed, 13 Jan 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4598243)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4598243");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Windows DNS Query.

  - An error in Windows AppX Deployment Extensions.

  - An error in Windows Docker.

  - An error in Microsoft splwow64.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges and disclose sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 x32/x64

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4598243");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Calc.exe");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.4168"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Calc.exe",
                            file_version:fileVer, vulnerable_range:"10.0.14393.0 - 10.0.14393.4168");
  security_message(data:report);
  exit(0);
}
exit(99);
