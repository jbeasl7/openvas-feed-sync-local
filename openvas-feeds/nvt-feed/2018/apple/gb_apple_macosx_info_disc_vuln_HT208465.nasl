# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812662");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2017-5754");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-05 11:31:00 +0000 (Tue, 05 May 2020)");
  script_tag(name:"creation_date", value:"2018-01-24 10:47:13 +0530 (Wed, 24 Jan 2018)");
  script_name("Apple Mac OS X Speculative Execution Side-Channel Vulnerability-Meltdown (HT208465)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as systems with
  microprocessors utilizing speculative execution and indirect branch prediction
  may allow unauthorized disclosure of information to an attacker with local user
  access via a side-channel analysis of the data cache.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to read kernel memory (Meltdown).");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.12.x through
  10.12.6 before build 16G1212 and 10.11.x through 10.11.6 before build 15G19009.");

  script_tag(name:"solution", value:"Apply the supplemental update from the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208465");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102378");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[12]");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[12]"){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"10.11", test_version2:"10.11.5") ||
   version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

else if(osVer == "10.11.6" || osVer == "10.12.6")
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(buildVer)
  {
    ##https://en.wikipedia.org/wiki/MacOS_Sierra
    ##https://en.wikipedia.org/wiki/OS_X_El_Capitan
    if((osVer == "10.11.6" && version_is_less(version:buildVer, test_version:"15G19009")) ||
       (osVer == "10.12.6" && version_is_less(version:buildVer, test_version:"16G1212")))
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