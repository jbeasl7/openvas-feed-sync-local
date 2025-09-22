# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810210");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5096", "CVE-2013-7456",
                "CVE-2016-4637", "CVE-2016-4629", "CVE-2016-4630", "CVE-2016-1836",
                "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4483", "CVE-2016-4614",
                "CVE-2016-4615", "CVE-2016-4616", "CVE-2016-4619", "CVE-2016-4449",
                "CVE-2016-1684", "CVE-2016-4607", "CVE-2016-4608", "CVE-2016-4609",
                "CVE-2016-4610", "CVE-2016-4612", "CVE-2016-1798", "CVE-2015-8126");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-11-22 11:05:47 +0530 (Tue, 22 Nov 2016)");
  script_name("Apple Mac OS X Code Execution And Denial of Service Vulnerabilities");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to code execution and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - a null pointer dereference error

  - an improper processing of .png file by libpng

  - multiple memory corruption errors

  - an access issue in the parsing of maliciously crafted XML files

  - multiple errors in PHP");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service and to obtain sensitive
  information.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.10.x through
  10.10.5 prior to build 14F1808");

  script_tag(name:"solution", value:"Apply the appropriate patch.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206567");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90696");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77568");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206903");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.10");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName && osVer =~ "^10\.10")
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }

  if(osVer == "10.10.5" && version_is_less(version:buildVer, test_version:"14F1808"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }

  else if(version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.4")){
    fix = "10.10.5 build 14F1808";
  }
}
if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
