# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836576");
  script_version("2025-08-15T15:42:26+0000");
  script_cve_id("CVE-2025-53778", "CVE-2025-53725", "CVE-2025-53766", "CVE-2025-53718",
                "CVE-2025-53724", "CVE-2025-50155", "CVE-2025-53722", "CVE-2025-53153",
                "CVE-2025-53141", "CVE-2025-53148", "CVE-2025-50163", "CVE-2025-50154",
                "CVE-2025-50157", "CVE-2025-53726", "CVE-2025-53723", "CVE-2025-53721",
                "CVE-2025-53720", "CVE-2025-53719", "CVE-2025-53716", "CVE-2025-53155",
                "CVE-2025-53154", "CVE-2025-53152", "CVE-2025-53151", "CVE-2025-53149",
                "CVE-2025-53147", "CVE-2025-53145", "CVE-2025-53144", "CVE-2025-53143",
                "CVE-2025-53140", "CVE-2025-53138", "CVE-2025-53137", "CVE-2025-53136",
                "CVE-2025-53135", "CVE-2025-53134", "CVE-2025-53132", "CVE-2025-53131",
                "CVE-2025-50177", "CVE-2025-50173", "CVE-2025-50172", "CVE-2025-50170",
                "CVE-2025-50167", "CVE-2025-50166", "CVE-2025-50164", "CVE-2025-50162",
                "CVE-2025-50161", "CVE-2025-50160", "CVE-2025-50159", "CVE-2025-50158",
                "CVE-2025-50156", "CVE-2025-50153", "CVE-2025-49762", "CVE-2025-49761",
                "CVE-2025-49743", "CVE-2025-49751");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-12 18:15:45 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-13 09:40:48 +0530 (Wed, 13 Aug 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5063877)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5063877");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  conduct spoofing and denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5063877");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2019:1) <= 0) {
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.7670")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.7670");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);