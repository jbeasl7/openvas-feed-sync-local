# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811536");
  script_version("2024-02-16T14:37:06+0000");
  script_cve_id("CVE-2017-7016", "CVE-2017-7033", "CVE-2017-7015", "CVE-2017-7050",
                "CVE-2017-7054", "CVE-2017-7062", "CVE-2017-7008", "CVE-2016-9586",
                "CVE-2016-9594", "CVE-2017-2629", "CVE-2017-7468", "CVE-2017-7014",
                "CVE-2017-7017", "CVE-2017-7035", "CVE-2017-7044", "CVE-2017-7036",
                "CVE-2017-7045", "CVE-2017-7025", "CVE-2017-7027", "CVE-2017-7069",
                "CVE-2017-7026", "CVE-2017-7068", "CVE-2017-9417");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 14:37:06 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-20 12:23:38 +0530 (Thu, 20 Jul 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities (HT207922)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow error.

  - Multiple input validation issues.

  - Multiple issues in curl.

  - An input validation issue.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information, gain extra privileges and execute arbitrary code.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.12.x before
  10.12.6");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.12.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99882");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99883");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99880");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95019");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95094");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96382");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97962");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99482");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.12");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName && osVer =~ "^10\.12")
{
  if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.5"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.12.6");
    security_message(data:report);
    exit(0);
  }
}

exit(99);
