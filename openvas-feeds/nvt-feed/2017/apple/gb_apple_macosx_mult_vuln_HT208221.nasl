# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811959");
  script_version("2024-02-16T14:37:06+0000");
  script_cve_id("CVE-2017-1000100", "CVE-2017-1000101", "CVE-2017-13801", "CVE-2017-13804",
                "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13080", "CVE-2017-7170");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 14:37:06 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-27 17:22:00 +0000 (Fri, 27 Apr 2018)");
  script_tag(name:"creation_date", value:"2017-11-02 12:40:42 +0530 (Thu, 02 Nov 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities (HT208221)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A logic issue existed in the handling of state transitions.

  - A path handling issue.

  - A validation issue existed which allowed local file access.

  - An out-of-bounds read.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code with system privileges and disclose sensitive information.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.13, 10.12.x
  through 10.12.6 prior to Security Update 2017-001 Sierra, 10.11.x through
  10.11.6 prior to Security Update 2017-004 El Capitan.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.13.1 or apply the appropriate patch.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208221");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100249");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101274");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[1-3]");
  exit(0);
}
include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[1-3]" || "Mac OS X" >!< osName){
  exit(0);
}

# if 10.11.x before 10.11.6 is running, update to 10.11.6 first and then apply patch
# if 10.12.x before 10.12.6 is running, update to 10.12.6 first and then apply patch
if(osVer =~ "^10\.1[12]")
{
  if(version_in_range(version:osVer, test_version:"10.11", test_version2:"10.11.5") ||
     version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.11.6" || osVer == "10.12.6")
  {
    buildVer = get_kb_item("ssh/login/osx_build");
    # applying patch on 10.11.6 will upgrade build version to 15G17023
    # http://www.insanelymac.com/forum/topic/306535-nvidia-web-driver-updates-for-el-capitan-update-07212017/page-35
    # applying patch on 10.12.6 will upgrade build version to 16G1036
    # http://www.xlr8yourmac.com/index.html#MacNvidiaDriverUpdates
    if(buildVer)
    {
      if((osVer == "10.11.6" && version_is_less(version:buildVer, test_version:"15G17023")) ||
         (osVer == "10.12.6" && version_is_less(version:buildVer, test_version:"16G1036")))
      {
        fix = "Apply patch from vendor";
        osVer = osVer + " Build " + buildVer;
      }
    }
  }
}

else if(osVer == "10.13"){
  fix = "10.13.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
