# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814422");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2018-4340", "CVE-2018-4419", "CVE-2018-4425", "CVE-2018-4371",
                "CVE-2018-4400", "CVE-2018-4402", "CVE-2018-4422", "CVE-2018-4423",
                "CVE-2018-4420", "CVE-2018-3640", "CVE-2018-4368", "CVE-2018-4413",
                "CVE-2018-4410", "CVE-2018-4415", "CVE-2018-4398", "CVE-2018-4394");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-05 19:20:00 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-11-02 10:56:30 +0530 (Fri, 02 Nov 2018)");
  script_name("Apple Mac OS X Security Updates (HT209193)-02");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption issues related to improper memory handling.

  - An out-of-bounds read issue related to improper input validation.

  - A validation issue was addressed with improper logic.

  - A logic issue was addressed with improper validation.

  - Systems with microprocessors utilizing speculative execution and that perform
    speculative reads of system registers may allow unauthorized disclosure of
    system parameters.

  - An issue existed in the method for determining prime numbers.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary code, gain elevated privileges, disclose sensitive
  information and cause denial of service condition.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.14.x prior to
  10.14.1, 10.12.x through 10.12.6 before build 16G1618 and 10.13.x through
  10.13.6 before build 17G3025");

  script_tag(name:"solution", value:"Apply the appropriate security patch. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209193");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[2-4]");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[2-4]" || "Mac OS X" >!< osName){
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.12")
{
  if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.12.6")
  {
    if(version_is_less(version:buildVer, test_version:"16G1618"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

else if(osVer =~ "^10\.13")
{
  if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.13.6")
  {
    if(version_is_less(version:buildVer, test_version:"17G3025"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

else if(osVer == "10.14"){
  fix = "10.14.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
