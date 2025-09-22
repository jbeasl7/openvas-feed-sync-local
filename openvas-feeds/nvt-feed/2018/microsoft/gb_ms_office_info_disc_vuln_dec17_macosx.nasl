# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812728");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2017-11934");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2018-01-11 14:22:59 +0530 (Thu, 11 Jan 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office PowerPoint Information Disclosure Vulnerability (Dec 2017) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2016 on Mac OS X according to Microsoft security
  update December 2017");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the way certain functions
  handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain sensitive information that may aid in launching further attacks.");

  script_tag(name:"affected", value:"Microsoft Office 2016 on Mac OS X.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.office.com/en-us/article/Release-notes-for-Office-2016-for-Mac-ed2da564-6d53-4542-9954-7e3209681a41?ui=en-US&rs=en-US&ad=US");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102064");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

if(!offVer = get_kb_item("MS/Office/MacOSX/Ver"))
  exit(0);

if(offVer =~ "^15\." && version_is_less(version:offVer, test_version:"15.41")) {
  report = report_fixed_ver(installed_version:offVer, fixed_version:"15.41.0 (Build 17120500)");
  security_message(data:report);
  exit(0);
}

exit(99);
