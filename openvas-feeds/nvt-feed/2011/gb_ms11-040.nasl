# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902444");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-1889");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 14:30:00 +0000 (Wed, 24 Jul 2024)");
  script_name("Microsoft Windows Threat Management Gateway Firewall Client Remote Code Execution Vulnerability (2520426)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2520426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48181");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms11-040");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-040");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error when setting proper bounds to the
  'NSPLookupServiceNext()' function, that allow remote code execution if an attacker leveraged a
  client computer to make specific requests on a system where the TMG firewall client is used.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code in the context of the application. Failed exploit attempts will result in
  denial-of-service conditions.");

  script_tag(name:"affected", value:"Microsoft Forefront Threat Management Gateway 2010 SP1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\";

if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  sysPath = registry_get_sz(key:key + item, item:"InstallRoot");

  if("Forefront TMG Client" >< sysPath)
  {
    dllVer = fetch_file_version(sysPath:sysPath, file_name:"Fwcmgmt.exe");
    if(!dllVer){
      exit(0);
    }

    if(version_is_less(version:dllVer, test_version:"7.0.7734.182"))
    {
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"7.0.7734.182", install_path:sysPath);
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
