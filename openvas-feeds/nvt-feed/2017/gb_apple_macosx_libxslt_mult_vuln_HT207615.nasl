# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810981");
  script_version("2024-02-16T14:37:06+0000");
  script_cve_id("CVE-2017-2477");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 14:37:06 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-07 17:15:00 +0000 (Fri, 07 Apr 2017)");
  script_tag(name:"creation_date", value:"2017-05-19 12:01:54 +0530 (Fri, 19 May 2017)");
  script_name("Apple Mac OS X 'libxslt' Multiple Vulnerabilities (HT207615)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple memory corruption vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  memory corruption issues causes due to poor memory handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to cause a denial of service (memory corruption) or possibly have unspecified
  other impact via unknown vectors.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.11.x through
  10.11.6");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207615");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.11");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.11" || "Mac OS X" >!< osName){
  exit(0);
}

## 10.11.6 before build 15G1421 is vulnerable
##if 10.11.5 or less is running, update to 10.11.6 then apply patch
if(version_in_range(version:osVer, test_version:"10.11", test_version2:"10.11.5")){
  fix = "Upgrade to latest OS release and apply patch from vendor";
}

## applying patch on 10.11.6 will upgrade build version to 15G1421
else if(version_is_equal(version:osVer, test_version:"10.11.6"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(buildVer && version_is_less(version:buildVer, test_version:"15G1421"))
  {
    osVer = osVer + " Build " + buildVer;
    report = report_fixed_ver(installed_version:osVer, fixed_version:"Apply patch from vendor");
    security_message(data:report);
    exit(0);
  }
}

exit(99);
