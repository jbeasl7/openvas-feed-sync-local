# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815822");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-8787", "CVE-2019-8785", "CVE-2019-8797", "CVE-2019-8717",
                "CVE-2019-8786", "CVE-2019-8824");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-26 13:24:00 +0000 (Thu, 26 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-10-30 12:08:41 +0530 (Wed, 30 Oct 2019)");
  script_name("Apple Mac OS X Security Updates (HT210722)-04");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Multiple memory corruption issues related to improper memory handling.

  - An out-of-bounds read");

  script_tag(name:"impact", value:"Successful exploitation allow attackers
  to gain access to sensitive information and execute arbitrary code with
  kernel privileges.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.15, 10.13.x
  prior to 10.13.6 Security Update 2019-006 and 10.14.x prior to 10.14.6
  Security Update 2019-001.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.15.1 or
  later or apply Security Update 2019-006 on 10.13.6 or apply
  Security Update 2019-001 on 10.14.6.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210722");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");

  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[345]" || "Mac OS X" >!< osName){
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.13")
{
  if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.13.6")
  {
    if(osVer == "10.13.6" && version_is_less(version:buildVer, test_version:"17G9016"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

if(osVer =~ "^10\.14")
{
  if(version_in_range(version:osVer, test_version:"10.14", test_version2:"10.14.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.14.6")
  {
    if(osVer == "10.14.6" && version_is_less(version:buildVer, test_version:"18G1012"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

else if(osVer == "10.15"){
  fix = "10.15.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
