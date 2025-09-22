# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810786");
  script_version("2025-02-12T05:37:43+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-0261", "CVE-2017-0262");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-12 05:37:43 +0000 (Wed, 12 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-11 17:02:35 +0000 (Tue, 11 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-05-10 13:29:20 +0530 (Wed, 10 May 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerabilities (KB3172458)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office Suite according to Microsoft KB3172458");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist in Microsoft Office software
  when the software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user on an
  affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0261");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98104");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98279");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0262");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3172458");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS Office
offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

if(offVer =~ "^15\..*")
{
  filePath = path + "\Microsoft Shared\TextConv";

  fileVer = fetch_file_version(sysPath:filePath, file_name:"wpequ532.dll");
  if(fileVer =~ "^2012")
  {
    if(version_in_range(version:fileVer, test_version:"2012", test_version2:"2012.1500.4454.0999"))
    {
      report = 'File checked:     ' + filePath + "\wpequ532.dll" + '\n' +
               'File version:     ' + fileVer  + '\n' +
               'Vulnerable range: ' + "2012 - 2012.1500.4454.0999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
