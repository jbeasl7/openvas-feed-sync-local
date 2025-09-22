# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810797");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8509", "CVE-2017-8511", "CVE-2017-8512");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-06-14 14:38:31 +0530 (Wed, 14 Jun 2017)");
  script_name("Microsoft Office 2013 Service Pack 1 Multiple Vulnerabilities (KB3203386)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3203386");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A remote code execution vulnerability exists in Microsoft Office software
    when the Office software fails to properly handle objects in memory.

  - A remote code execution vulnerability exists in Microsoft Office software
    when the Office software fails to properly handle objects in memory.

  - A remote code execution vulnerability exists in Microsoft Office software
    when the Office software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3203386");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98812");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98815");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98816");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS Office Version
officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

commonpath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!commonpath){
  exit(0);
}

if(officeVer =~ "^(15\.)")
{
  ##Office Path
  offPath = commonpath + "\Microsoft Shared\Office15";

  offexeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");

  if(offexeVer && version_in_range(version:offexeVer, test_version:"15.0", test_version2:"15.0.4937.0999"))
  {
    report = 'File checked:     ' + offPath + "\Mso.dll" + '\n' +
             'File version:     ' + offexeVer  + '\n' +
             'Vulnerable range: ' + "15.0 - 15.0.4937.0999" + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);

