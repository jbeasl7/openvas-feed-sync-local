# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810571");
  script_version("2024-02-19T14:37:31+0000");
  script_cve_id("CVE-2016-4683", "CVE-2016-4671", "CVE-2016-4681");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 14:37:31 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-02-28 09:04:00 +0530 (Tue, 28 Feb 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-05 (Feb 2017)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A memory corruption issue in 'Core Image'.

  - Multiple out-of-bounds read and write errors in 'SGI parsing'.

  - An out-of-bounds write error in 'ImageIO'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.11.x through
  10.11.6");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.12.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207275");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.11");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.11"){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"10.11", test_version2:"10.11.5")){
  fix = "Upgrade to latest OS release and apply patch from vendor";
}

else if(osVer == "10.11.6")
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(buildVer)
  {
    if(osVer == "10.11.6" && version_is_less(version:buildVer, test_version:"15G1108"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
