# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811824");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-8725");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-21 15:58:00 +0000 (Thu, 21 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-13 13:18:52 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Publisher 2007 Service Pack 3 Remote Code Execution Vulnerability (KB3114428)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3114428");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Microsoft Office
  software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited the vulnerability to use a specially
  crafted file to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft Publisher 2007 Service Pack 3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3114428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100758");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Publisher/Version");

  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exeVer = get_kb_item("SMB/Office/Publisher/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Publisher/Installed/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

##Microsoft Publisher 2007
if(exeVer && exeVer =~ "^12.*")
{
  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6776.4999"))
  {
    report = 'File checked:     ' + exePath + 'mspub.exe'  + '\n' +
             'File version:     ' + exeVer  + '\n' +
             'Vulnerable range: ' + "12.0 - 12.0.6776.4999" + '\n' ;

    security_message(data:report);
    exit(0);
  }
}

exit(0);
