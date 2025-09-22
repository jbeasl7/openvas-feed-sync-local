# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814589");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2019-0585");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-01-09 14:39:59 +0530 (Wed, 09 Jan 2019)");
  script_name("Microsoft Office Word Viewer Remote Code Execution Vulnerability (KB4462112)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4462112");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when it fails to properly handle
  objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to view out of bound memory.");

  script_tag(name:"affected", value:"Microsoft Office Word Viewer.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4462112");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/106392");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/WordView/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

wordviewVer = get_kb_item("SMB/Office/WordView/Version");
if(!wordviewVer){
  exit(0);
}

wordviewPath = get_kb_item("SMB/Office/WordView/Install/Path");
if(!wordviewPath){
  wordviewPath = "Unable to fetch the install path";
}

if(wordviewVer =~ "^11\." && version_is_less(version:wordviewVer, test_version:"11.0.8454.0"))
{
  report = report_fixed_ver(file_checked:wordviewPath + 'wordview.exe',
                            file_version:wordviewVer, vulnerable_range:"11.0 - 11.0.8453.9");
  security_message(data:report);
  exit(0);
}
exit(99);
