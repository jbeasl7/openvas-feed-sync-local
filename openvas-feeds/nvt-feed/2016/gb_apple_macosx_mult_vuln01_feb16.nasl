# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806677");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2016-1716", "CVE-2016-1717", "CVE-2016-1718", "CVE-2016-1719",
                "CVE-2016-1720", "CVE-2016-1721", "CVE-2016-1722", "CVE-2016-1729",
                "CVE-2015-7995");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-22 19:34:00 +0000 (Fri, 22 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-02-03 18:07:12 +0530 (Wed, 03 Feb 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 (Feb 2016)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption errors in the parsing of disk images and IOHIDFamily
    API.

  - A type confusion error within libxslt.

  - Other multiple memory corruption errors.

  - An error when searching for scripting libraries.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code, override OSA script libraries.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.9.x through
  10.9.5 prior to build 13F1603, 10.10.x through 10.10.5 prior to build 14F1605
  and 10.11.x before 10.11.3");

  script_tag(name:"solution", value:"Upgrade Apple Mac OS X 10.11.x to version
  10.11.3 or later or apply appropriate patch for Apple Mac OS X 10.9.x and 10.10.x. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205731");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/81274");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/81277");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77325");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2016/Jan/msg00003.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[1-3]");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[1-3]"){
  exit(0);
}

if(osVer =~ "^10\.(9|10)")
{
  if(version_in_range(version:osVer, test_version:"10.9", test_version2:"10.9.4") ||
     version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.4")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.10.5" || osVer == "10.9.5")
  {
    buildVer = get_kb_item("ssh/login/osx_build");
    if(buildVer)
    {
      if((osVer == "10.10.5" && version_is_less(version:buildVer, test_version:"14F1605")) ||
         (osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F1603")))
      {
        fix = "Apply patch from vendor";
        osVer = osVer + " Build " + buildVer;
      }
    }
  }
}

else if(version_in_range(version:osVer, test_version:"10.11", test_version2:"10.11.2")){
  fix = "10.11.3";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
