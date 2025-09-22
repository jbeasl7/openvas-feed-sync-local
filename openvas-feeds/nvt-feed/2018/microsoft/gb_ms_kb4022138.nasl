# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814124");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-8501");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-10-10 11:51:21 +0530 (Wed, 10 Oct 2018)");
  script_name("Microsoft PowerPoint Viewer 2010 Remote Code Execution Vulnerability (KB4022138)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4022138");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in Microsoft PowerPoint when
  the software fails to properly handle objects in Protected View.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft PowerPoint Viewer 2010.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4022138");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PPView/Version");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

ppviewVer = get_kb_item("SMB/Office/PPView/Version");
if(!ppviewVer){
  exit(0);
}

ppviewPath =  get_kb_item("SMB/Office/PPView/FilePath");
if(!ppviewPath){
  ppviewPath = "Unable to get installation path";
}

if(ppviewVer =~ "^(14\.)" && version_is_less(version:ppviewVer, test_version:"14.0.7214.5000"))
{
  report = report_fixed_ver(file_checked:ppviewPath + "\pptview.exe",
                            file_version:ppviewVer, vulnerable_range:"14.0 - 14.0.7214.4999");
  security_message(data:report);
}
exit(0);
