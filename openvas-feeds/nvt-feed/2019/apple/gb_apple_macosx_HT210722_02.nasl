# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815820");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-11041", "CVE-2019-11042", "CVE-2019-8509", "CVE-2019-8850",
                "CVE-2019-8708", "CVE-2019-8709", "CVE-2019-8745", "CVE-2019-8705",
                "CVE-2019-8706", "CVE-2019-8744", "CVE-2019-8746", "CVE-2019-8767",
                "CVE-2019-8748", "CVE-2019-8761", "CVE-2019-8831", "CVE-2019-8825",
                "CVE-2019-8749", "CVE-2019-8756", "CVE-2019-8716", "CVE-2019-8715",
                "CVE-2018-12152", "CVE-2018-12153", "CVE-2018-12154", "CVE-2019-8759",
                "CVE-2019-8592", "CVE-2019-8737", "CVE-2019-8736", "CVE-2019-8750",
                "CVE-2019-8772", "CVE-2019-8796");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-29 16:03:00 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-10-30 12:08:31 +0530 (Wed, 30 Oct 2019)");
  script_name("Apple Mac OS X Security Updates (HT210722)-02");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - This issue related to existence of vulnerable code.

  - A logic issue related to improper restrictions.

  - A memory corruption issue related to improper state management.

  - A memory corruption issue existed in the handling of IPv6 packets.

  - A memory consumption issue related to improper memory handling.

  - An issue related to improper checks.

  - Multiple memory corruption issues related to improper input validation.

  - An out-of-bounds read error related to improper bounds checking.

  - A denial of service issue related to improper validation.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers
  to elevate privileges, check for the existence of arbitrary files, conduct
  arbitrary code execution, determine kernel memory layout, disclosure of user
  information, exfiltrate the contents of an encrypted PDF and cause unexpected
  system termination or read kernel memory.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.13.x through 10.13.6
  prior to Security Update 2019-006, 10.14.x through 10.14.6 prior to
  Security Update 2019-001.");

  script_tag(name:"solution", value:"Apply security update 2019-001 for 10.14.x and
  Security Update 2019-006 for 10.13.x from vendor.");

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
if(!osVer || osVer !~ "^10\.1[34]" || "Mac OS X" >!< osName){
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

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}
