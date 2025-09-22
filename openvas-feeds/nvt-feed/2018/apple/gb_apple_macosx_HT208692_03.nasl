# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813114");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2017-8816", "CVE-2017-13890");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-13 11:29:00 +0000 (Tue, 13 Nov 2018)");
  script_tag(name:"creation_date", value:"2018-04-02 10:46:36 +0530 (Mon, 02 Apr 2018)");
  script_name("Apple Mac OS X Security Updates (HT208692)-03");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An integer overflow in curl.

  - A logic issue due to improper restrictions.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers into mounting of a disk image, code execution and
  denial-of-service condition.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.11.x through
  10.11.6, 10.12.x through 10.12.6");

  script_tag(name:"solution", value:"Apply the appropriate patch.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208692");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[12]");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[12]" || "Mac OS X" >!< osName){
  exit(0);
}

if((osVer == "10.11.6") || (osVer == "10.12.6"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }

  if(osVer == "10.11.6" && version_is_less(version:buildVer, test_version:"15G20015"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }

  else if(osVer == "10.12.6" && version_is_less(version:buildVer, test_version:"16G1314"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

if(osVer =~ "^10\.11")
{
  if(version_is_less(version:osVer, test_version:"10.11.6")){
    fix = "Upgrade to latest OS release 10.11.6 and apply patch from vendor";
  }
}

else if(osVer =~ "^10\.12")
{
  if(version_is_less(version:osVer, test_version:"10.12.6")){
    fix = "Upgrade to latest OS release 10.12.6 and apply patch from vendor";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
