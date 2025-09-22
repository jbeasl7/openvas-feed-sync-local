# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807801");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-0145");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-04-13 12:03:48 +0530 (Wed, 13 Apr 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Viewer Remote Code Execution Vulnerability (3148522)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-039.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in font library
  while handling specially crafted embedded fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Word Viewer.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3148522");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114985");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-039");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/WordView/Version");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms16-039");
  exit(0);
}


include("version_func.inc");

wordviewVer = get_kb_item("SMB/Office/WordView/Version");
if(wordviewVer)
{
  ## Wordview.exe will update for https://support.microsoft.com/en-us/kb/3114478
  if(version_in_range(version:wordviewVer, test_version:"11.0", test_version2:"11.0.8425"))
  {
    report = 'File checked:     Wordview.exe ' + '\n' +
             'File version:     ' + wordviewVer  + '\n' +
             'Vulnerable range: 11.0 - 11.0.8425 \n' ;
    security_message(data:report);
    exit(0);
  }
}
