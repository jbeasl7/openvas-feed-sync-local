# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834874");
  script_version("2025-02-07T05:37:57+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2025-21217", "CVE-2025-21246", "CVE-2025-21334", "CVE-2025-21374",
                "CVE-2025-21343", "CVE-2025-21340", "CVE-2025-21312", "CVE-2025-21300",
                "CVE-2025-21276", "CVE-2025-21189", "CVE-2025-21229", "CVE-2025-21331",
                "CVE-2025-21324", "CVE-2025-21227", "CVE-2025-21310", "CVE-2025-21202",
                "CVE-2025-21409", "CVE-2025-21333", "CVE-2025-21207", "CVE-2025-21223",
                "CVE-2025-21232", "CVE-2025-21228", "CVE-2025-21330", "CVE-2025-21307",
                "CVE-2025-21275", "CVE-2025-21231", "CVE-2025-21341", "CVE-2025-21318",
                "CVE-2025-21245", "CVE-2025-21240", "CVE-2025-21250", "CVE-2025-21338",
                "CVE-2025-21317", "CVE-2025-21292", "CVE-2025-21230", "CVE-2025-21224",
                "CVE-2025-21211", "CVE-2025-21328", "CVE-2025-21389", "CVE-2025-21327",
                "CVE-2025-21238", "CVE-2025-21210", "CVE-2025-21370", "CVE-2025-21305",
                "CVE-2025-21287", "CVE-2025-21274", "CVE-2025-21273", "CVE-2025-21256",
                "CVE-2025-21213", "CVE-2025-21335", "CVE-2025-21278", "CVE-2024-7344",
                "CVE-2025-21321", "CVE-2025-21319", "CVE-2025-21314", "CVE-2025-21306",
                "CVE-2025-21299", "CVE-2025-21280", "CVE-2025-21263", "CVE-2025-21257",
                "CVE-2025-21417", "CVE-2025-21332", "CVE-2025-21378", "CVE-2025-21339",
                "CVE-2025-21336", "CVE-2025-21323", "CVE-2025-21308", "CVE-2025-21286",
                "CVE-2025-21261", "CVE-2025-21226", "CVE-2025-21220", "CVE-2025-21329",
                "CVE-2025-21219", "CVE-2025-21382", "CVE-2025-21320", "CVE-2025-21316",
                "CVE-2025-21303", "CVE-2025-21302", "CVE-2025-21301", "CVE-2025-21298",
                "CVE-2025-21296", "CVE-2025-21295", "CVE-2025-21294", "CVE-2025-21293",
                "CVE-2025-21291", "CVE-2025-21290", "CVE-2025-21289", "CVE-2025-21288",
                "CVE-2025-21285", "CVE-2025-21284", "CVE-2025-21282", "CVE-2025-21281",
                "CVE-2025-21277", "CVE-2025-21272", "CVE-2025-21270", "CVE-2025-21269",
                "CVE-2025-21268", "CVE-2025-21266", "CVE-2025-21265", "CVE-2025-21260",
                "CVE-2025-21258", "CVE-2025-21255", "CVE-2025-21252", "CVE-2025-21251",
                "CVE-2025-21249", "CVE-2025-21248", "CVE-2025-21244", "CVE-2025-21243",
                "CVE-2025-21242", "CVE-2025-21241", "CVE-2025-21239", "CVE-2025-21237",
                "CVE-2025-21236", "CVE-2025-21235", "CVE-2025-21234", "CVE-2025-21233",
                "CVE-2025-21215", "CVE-2025-21214", "CVE-2025-21413", "CVE-2025-21411",
                "CVE-2025-21325");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-07 05:37:57 +0000 (Fri, 07 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-14 18:15:53 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-15 09:57:15 +0530 (Wed, 15 Jan 2025)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5050021)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5050021");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, spoofing and conduct denial of service
  attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 11 version 22H2 for x64-based Systems

  - Microsoft Windows 11 Version 23H2 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5050021");
  script_xref(name:"URL", value:"https://www.welivesecurity.com/en/eset-research/under-cloak-uefi-secure-boot-introducing-cve-2024-7344/");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/529659");
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

if(hotfix_check_sp(win11:1) <= 0) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)) {
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build || (build != "22621" && build != "22631")) {
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

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.4745")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\ntoskrnl.exe", file_version:fileVer,
                            vulnerable_range:"10.0.22621.0 - 10.0.22621.4745");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
