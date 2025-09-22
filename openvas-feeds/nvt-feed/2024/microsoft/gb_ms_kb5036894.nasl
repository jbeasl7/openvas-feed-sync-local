# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832912");
  script_version("2024-08-09T05:05:42+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-0001", "CVE-2024-20665", "CVE-2024-26180", "CVE-2024-26230",
                "CVE-2024-26241", "CVE-2024-29062", "CVE-2024-28923", "CVE-2024-26254",
                "CVE-2024-26253", "CVE-2024-20678", "CVE-2024-29052", "CVE-2024-26211",
                "CVE-2024-29050", "CVE-2024-21447", "CVE-2024-26244", "CVE-2024-28901",
                "CVE-2024-26217", "CVE-2024-26232", "CVE-2024-29064", "CVE-2024-28903",
                "CVE-2024-23594", "CVE-2024-29988", "CVE-2024-28898", "CVE-2024-26218",
                "CVE-2024-29061", "CVE-2024-26172", "CVE-2024-26243", "CVE-2024-26229",
                "CVE-2024-26240", "CVE-2024-26239", "CVE-2024-26194", "CVE-2024-20669",
                "CVE-2024-23593", "CVE-2024-26214", "CVE-2024-26252", "CVE-2024-26220",
                "CVE-2024-28902", "CVE-2024-28900", "CVE-2024-28897", "CVE-2024-28896",
                "CVE-2024-28925", "CVE-2024-28924", "CVE-2024-28919", "CVE-2024-28921",
                "CVE-2024-28922", "CVE-2024-28920", "CVE-2024-26228", "CVE-2024-26208",
                "CVE-2024-26207", "CVE-2024-26242", "CVE-2024-26237", "CVE-2024-26234",
                "CVE-2024-26210", "CVE-2024-26158", "CVE-2024-26205", "CVE-2024-26200",
                "CVE-2024-26179", "CVE-2024-26255", "CVE-2024-26250", "CVE-2024-26248",
                "CVE-2024-26219", "CVE-2024-26209", "CVE-2024-26189", "CVE-2024-26183",
                "CVE-2024-26175", "CVE-2024-26171", "CVE-2024-26168", "CVE-2024-20693");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-09 17:16:01 +0000 (Tue, 09 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-10 12:02:12 +0530 (Wed, 10 Apr 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5036894)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5036894");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-29062: Secure Boot Security Feature Bypass Vulnerability

  - CVE-2024-26229: Windows CSC Service Elevation of Privilege Vulnerability

  - CVE-2024-26180: Secure Boot Security Feature Bypass Vulnerability

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, conduct spoofing and denial of service
  attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 21H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5036894");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(hotfix_check_sp(win11:1) <= 0) {
  exit(0);
}

dllPath = smb_get_systemroot();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"\system32\ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"10.0.22000.2899")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\ntoskrnl.exe", file_version:fileVer, vulnerable_range:"Less than 10.0.22000.2899");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
