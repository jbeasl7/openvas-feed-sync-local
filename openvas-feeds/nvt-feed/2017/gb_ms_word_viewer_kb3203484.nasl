# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810953");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-0285");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-31 19:20:00 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"creation_date", value:"2017-06-20 15:46:19 +0530 (Tue, 20 Jun 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Viewer Information Disclosure Vulnerability (KB3203484)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3203484.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Windows Uniscribe
  improperly discloses the contents of its memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to obtain information to further compromise the user's system.");

  script_tag(name:"affected", value:"Microsoft Word Viewer.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3203484");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98914");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/WordView/Version");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!wordviewPath = get_kb_item("SMB/Office/WordView/Install/Path")){
  exit(0);
}

if(!dllVer = fetch_file_version(sysPath:wordviewPath, file_name:"gdiplus.dll")){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"11.0.8442"))
{
  report = 'File checked:     ' + wordviewPath + "gdiplus.dll" + '\n' +
           'File version:     ' + dllVer + '\n' +
           'Vulnerable range: Less than 11.0.8442 \n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
