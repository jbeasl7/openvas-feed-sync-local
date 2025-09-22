# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816827");
  script_version("2024-06-26T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-0687", "CVE-2020-0784", "CVE-2020-0821", "CVE-2020-0889",
                "CVE-2020-0895", "CVE-2020-0907", "CVE-2020-0936", "CVE-2020-0937",
                "CVE-2020-0938", "CVE-2020-0940", "CVE-2020-0942", "CVE-2020-0945",
                "CVE-2020-0946", "CVE-2020-0948", "CVE-2020-0949", "CVE-2020-0950",
                "CVE-2020-0952", "CVE-2020-0953", "CVE-2020-0955", "CVE-2020-0956",
                "CVE-2020-0958", "CVE-2020-0959", "CVE-2020-0960", "CVE-2020-0962",
                "CVE-2020-0964", "CVE-2020-0965", "CVE-2020-0966", "CVE-2020-0967",
                "CVE-2020-0968", "CVE-2020-0969", "CVE-2020-0982", "CVE-2020-0983",
                "CVE-2020-0985", "CVE-2020-0987", "CVE-2020-0988", "CVE-2020-0992",
                "CVE-2020-0993", "CVE-2020-0994", "CVE-2020-0995", "CVE-2020-0999",
                "CVE-2020-1000", "CVE-2020-1003", "CVE-2020-1004", "CVE-2020-1005",
                "CVE-2020-1006", "CVE-2020-1007", "CVE-2020-1008", "CVE-2020-1009",
                "CVE-2020-1011", "CVE-2020-1014", "CVE-2020-1015", "CVE-2020-1016",
                "CVE-2020-1017", "CVE-2020-1020", "CVE-2020-1027", "CVE-2020-1094");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-17 18:03:00 +0000 (Fri, 17 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 08:39:55 +0530 (Wed, 15 Apr 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4550929)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4550929");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the way that the scripting engine handles objects in memory
    in Internet Explorer.

  - Multiple errors when the Microsoft Windows Graphics Component improperly
    handles objects in memory.

  - An error when the Windows Jet Database Engine improperly handles objects
    in memory.

  - An error when the Windows update stack fails to properly handle objects in
    memory.

  - An error when the Windows Delivery Optimization service improperly handles
    objects in memory.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privileges, disclose sensitive information and
  conduct denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 x32/x64

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4550929");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Ntoskrnl.exe");
if(!dllVer)
  exit(0);

if(version_in_range(version:dllVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.3629")) {
  report = report_fixed_ver(file_checked:sysPath + "\Ntoskrnl.exe",
                            file_version:dllVer, vulnerable_range:"10.0.14393.0 - 10.0.14393.3629");
  security_message(data:report);
  exit(0);
}

exit(99);
