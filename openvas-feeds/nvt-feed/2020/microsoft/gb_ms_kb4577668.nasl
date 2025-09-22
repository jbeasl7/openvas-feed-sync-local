# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817487");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2020-0764", "CVE-2020-1047", "CVE-2020-1080", "CVE-2020-1167",
                "CVE-2020-1243", "CVE-2020-16876", "CVE-2020-16885", "CVE-2020-16887",
                "CVE-2020-16889", "CVE-2020-16890", "CVE-2020-16891", "CVE-2020-16892",
                "CVE-2020-16895", "CVE-2020-16896", "CVE-2020-16897", "CVE-2020-16898",
                "CVE-2020-16899", "CVE-2020-16900", "CVE-2020-16902", "CVE-2020-16905",
                "CVE-2020-16907", "CVE-2020-16909", "CVE-2020-16910", "CVE-2020-16911",
                "CVE-2020-16912", "CVE-2020-16913", "CVE-2020-16914", "CVE-2020-16915",
                "CVE-2020-16916", "CVE-2020-16919", "CVE-2020-16920", "CVE-2020-16921",
                "CVE-2020-16922", "CVE-2020-16923", "CVE-2020-16924", "CVE-2020-16927",
                "CVE-2020-16935", "CVE-2020-16936", "CVE-2020-16939", "CVE-2020-16940",
                "CVE-2020-16967", "CVE-2020-16968", "CVE-2020-16972", "CVE-2020-16973",
                "CVE-2020-16974", "CVE-2020-16975", "CVE-2020-16976", "CVE-2020-16980",
                "CVE-2020-17022");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-23 18:36:00 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-14 08:49:58 +0530 (Wed, 14 Oct 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4577668)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4577668");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to errors,

  - Windows Hyper-V on a host server fails to properly handle objects in memory.

  - Windows Network Connections Service improperly handles objects in memory.

  - Windows KernelStream improperly handles objects in memory.

  - Windows TCP/IP stack improperly handles ICMPv6 Router Advertisement packets.

  - Microsoft Windows fails to handle file creation permissions.

  - Microsoft Windows Codecs Library improperly handles objects in memory.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privileges, conduct DoS condition, bypass security restrictions
  and disclose sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1809 x32/x64

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4577668");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-17022");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2019:1) <= 0){
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

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.1517"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Gdiplus.dll",
                            file_version:fileVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.1517");
  security_message(data:report);
  exit(0);
}
exit(99);
