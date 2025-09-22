# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810569");
  script_version("2024-02-19T14:37:31+0000");
  script_cve_id("CVE-2016-7584", "CVE-2016-4678", "CVE-2016-4667", "CVE-2016-4674",
                "CVE-2016-7579", "CVE-2016-4673", "CVE-2016-7577", "CVE-2016-4660",
                "CVE-2016-4688", "CVE-2016-4721", "CVE-2016-4669", "CVE-2016-7613",
                "CVE-2016-4679", "CVE-2016-4675", "CVE-2016-4661", "CVE-2016-4670",
                "CVE-2016-4780");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 14:37:31 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-22 19:58:00 +0000 (Fri, 22 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-02-28 09:04:00 +0530 (Tue, 28 Feb 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-03 (Feb 2017)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple null pointer dereference errors.

  - A logging issue in the handling of passwords.

  - An issue existed in the parsing of disk images.

  - A logic issue in libxpc.

  - An issue within the path validation logic for symlinks in libarchive.

  - Multiple object lifetime issues existed when spawning new processes.

  - Multiple input validation issues existed in MIG generated code.

  - An impersonation issue existed in the handling of call switching
    in the IDS - Connectivity.

  - A buffer overflow existed in the handling of font files.

  - An out-of-bounds read error in FontParser.

  - An user interface inconsistencies existed in the handling of relayed calls
    in FaceTime.

  - A phishing issue existed in the handling of proxy credentials.

  - Multiple memory corruption errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service, elevate privileges,
  gain access to potentially sensitive information and overwrite arbitrary files.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.10.x through
  10.10.5 prior to build 14F2009, 10.11.x prior to build 15G1108 and 10.12.x prior
  to 10.12.1");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version 10.12.1
  or later or apply appropriate patch. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207275");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[0-2]");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[0-2]"){
  exit(0);
}

if(osVer =~ "^10\.1[01]")
{
  if(version_in_range(version:osVer, test_version:"10.10", test_version2:"10.11.5") ||
     version_in_range(version:osVer, test_version:"10.11", test_version2:"10.10.4")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.11.6" || osVer == "10.10.5")
  {
    buildVer = get_kb_item("ssh/login/osx_build");
    if(buildVer)
    {
      if((osVer == "10.11.6" && version_is_less(version:buildVer, test_version:"15G1108")) ||
         (osVer == "10.10.5" && version_is_less(version:buildVer, test_version:"14F2009")))
      {
        fix = "Apply patch from vendor";
        osVer = osVer + " Build " + buildVer;
      }
    }
  }
}

else if(osVer =~ "^10\." && version_is_less(version:osVer, test_version:"10.12.1")){
  fix = "10.12.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
