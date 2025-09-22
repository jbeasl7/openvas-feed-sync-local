# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806695");
  script_version("2024-02-19T14:37:31+0000");
  script_cve_id("CVE-2016-1754", "CVE-2016-1755", "CVE-2016-1759", "CVE-2016-1761",
                "CVE-2016-1765", "CVE-2015-8472", "CVE-2015-1819", "CVE-2015-5312",
                "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7942", "CVE-2015-8035",
                "CVE-2015-8242", "CVE-2016-1762", "CVE-2016-0777", "CVE-2016-0778",
                "CVE-2015-5333", "CVE-2015-5334", "CVE-2014-9495", "CVE-2015-0973",
                "CVE-2016-1791", "CVE-2016-1800", "CVE-2016-1833", "CVE-2016-1834",
                "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838",
                "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-1841", "CVE-2016-1847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 14:37:31 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:22:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:35 +0530 (Fri, 01 Apr 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-02 (Mar 2016)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, trigger a dialing action via a
  tel: URL, bypass a code-signing protection mechanism.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.9.x before 10.9.5
  and 10.10.x before 10.10.5");

  script_tag(name:"solution", value:"Apply the appropriate security patch from
  the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206567");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.(9|10)");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.(9|10)"){
  exit(0);
}

if((osVer == "10.9.5") || (osVer == "10.10.5"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }
  if(osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F1808"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
  else if(osVer == "10.10.5" && version_is_less(version:buildVer, test_version:"14F1808"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

else if(version_in_range(version:osVer, test_version:"10.9", test_version2:"10.9.4")){
  fix = "10.9.5 build 13F1808";
}
else if(version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.4")){
  fix = "10.10.5 build 14F1808";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
