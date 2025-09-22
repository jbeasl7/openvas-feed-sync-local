# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836108");
  script_version("2025-09-03T05:38:18+0000");
  script_cve_id("CVE-2025-27480", "CVE-2025-27735", "CVE-2025-27484", "CVE-2025-24060",
                "CVE-2025-27732", "CVE-2025-27491", "CVE-2025-27482", "CVE-2025-29809",
                "CVE-2025-27739", "CVE-2025-27738", "CVE-2025-27727", "CVE-2025-27730",
                "CVE-2025-27467", "CVE-2025-27737", "CVE-2025-27483", "CVE-2025-27736",
                "CVE-2025-27731", "CVE-2025-27487", "CVE-2025-27485", "CVE-2025-26640",
                "CVE-2025-27473", "CVE-2025-26666", "CVE-2025-29810", "CVE-2025-27733",
                "CVE-2025-27486", "CVE-2025-27481", "CVE-2025-27469", "CVE-2025-26679",
                "CVE-2025-26678", "CVE-2025-26676", "CVE-2025-26673", "CVE-2025-26672",
                "CVE-2025-26674", "CVE-2025-26671", "CVE-2025-26670", "CVE-2025-26652",
                "CVE-2025-26647", "CVE-2025-26648", "CVE-2025-26644", "CVE-2025-26641",
                "CVE-2025-26637", "CVE-2025-26635", "CVE-2025-24058", "CVE-2025-21222",
                "CVE-2025-21221", "CVE-2025-21204", "CVE-2025-21203", "CVE-2025-21205",
                "CVE-2025-21191", "CVE-2025-21197", "CVE-2025-21174", "CVE-2025-24073",
                "CVE-2025-24074", "CVE-2025-29824", "CVE-2025-27742", "CVE-2025-27741",
                "CVE-2025-27740", "CVE-2025-27479", "CVE-2025-27478", "CVE-2025-27477",
                "CVE-2025-27476", "CVE-2025-27474", "CVE-2025-27470", "CVE-2025-27471",
                "CVE-2025-26688", "CVE-2025-26687", "CVE-2025-26686", "CVE-2025-26680",
                "CVE-2025-26668", "CVE-2025-26667", "CVE-2025-26669", "CVE-2025-26665",
                "CVE-2025-26664", "CVE-2025-26663");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-08 18:16:02 +0000 (Tue, 08 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-09 10:08:14 +0530 (Wed, 09 Apr 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5055519)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5055519");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, bypass security
  restrictions, disclose information, conduct spoofing and denial of service
  attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5055519");
  script_xref(name:"URL", value:"https://securelist.com/pipemagic/117270/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
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

if(version_in_range(version:fileVer, test_version:"10.0.17763.0", test_version2:"10.0.17763.7130")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.17763.0 - 10.0.17763.7130");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
