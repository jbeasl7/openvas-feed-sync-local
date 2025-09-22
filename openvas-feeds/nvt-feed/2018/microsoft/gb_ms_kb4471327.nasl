# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814612");
  script_version("2023-07-20T05:05:18+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-8477", "CVE-2018-8514", "CVE-2018-8517", "CVE-2018-8540",
                "CVE-2018-8599", "CVE-2018-8611", "CVE-2018-8612", "CVE-2018-8617",
                "CVE-2018-8618", "CVE-2018-8619", "CVE-2018-8624", "CVE-2018-8625",
                "CVE-2018-8629", "CVE-2018-8631", "CVE-2018-8634", "CVE-2018-8639",
                "CVE-2018-8641", "CVE-2018-8643", "CVE-2018-8583", "CVE-2018-8595",
                "CVE-2018-8596");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 12:58:00 +0000 (Mon, 28 Sep 2020)");
  script_tag(name:"creation_date", value:"2018-12-12 10:03:10 +0530 (Wed, 12 Dec 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4471327)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4471327");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows kernel fails to properly handle objects in memory.

  - Chakra scripting engine improperly handles objects in memory in
    Microsoft Edge.

  - Connected User Experiences and Telemetry Service fails to validate
    certain function values.

  - Internet Explorer VBScript execution policy does not properly
    restrict VBScript under specific conditions.

  - Windows GDI component improperly discloses the contents of its
    memory.

  - Scripting engine improperly handles objects in memory in Internet
    Explorer.

  - VBScript engine improperly handles objects in memory.

  - Windows kernel-mode driver fails to properly handle objects in memory.

  - Internet Explorer improperly accesses objects in memory.

  - Windows Win32k component fails to properly handle objects in memory.

  - Microsoft text-to-speech fails to properly handle objects in the memory.

  - Diagnostics Hub Standard Collector Service improperly impersonates
    certain file operations.

  - Remote Procedure Call runtime improperly initializes objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in kernel mode, obtain sensitive information, deny dependent
  security feature functionality, gain elevated privileges and could take control
  of the affected system.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1703 x32/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4471327");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.15063.0", test_version2:"11.0.15063.1505"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.15063.0 - 11.0.15063.1505");
  security_message(data:report);
  exit(0);
}
exit(99);
