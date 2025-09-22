# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813191");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2014-4860", "CVE-2015-0235", "CVE-2015-0273", "CVE-2015-5924",
                "CVE-2015-5925", "CVE-2015-5926", "CVE-2015-5927", "CVE-2015-5933",
                "CVE-2015-5934", "CVE-2015-5936", "CVE-2015-5937", "CVE-2015-5939",
                "CVE-2015-5940", "CVE-2015-5942", "CVE-2015-6834", "CVE-2015-6835",
                "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-6838", "CVE-2015-6976",
                "CVE-2015-6977", "CVE-2015-6978", "CVE-2015-6980", "CVE-2015-6984",
                "CVE-2015-6985", "CVE-2015-6991", "CVE-2015-6992", "CVE-2015-6993",
                "CVE-2015-6996", "CVE-2015-7003", "CVE-2015-7009", "CVE-2015-7010",
                "CVE-2015-7018", "CVE-2015-7024");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-04 18:15:00 +0000 (Tue, 04 May 2021)");
  script_tag(name:"creation_date", value:"2018-05-15 15:17:32 +0530 (Tue, 15 May 2018)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 (HT205375)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist. Please see the
  references for more details.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code, unexpected application termination, exercise unused
  EFI functions, overwrite arbitrary files and load arbitrary files.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.9.x through
  10.9.5 prior to build 13F1134, 10.10.x through 10.10.5 prior to build 14F1021,
  and 10.11.x prior to 10.11.1");

  script_tag(name:"solution", value:"Upgrade 10.11.x Apple Mac OS X to version
  10.11.1 or apply the appropriate patch for 10.10.x and 10.9.x Apple Mac OS X
  versions. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205375");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.(9|1[01])");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.(9|1[01])"){
  exit(0);
}

if(osVer =~ "^10\.(9|10)")
{
  if(version_in_range(version:osVer, test_version:"10.9", test_version2:"10.9.4") ||
     version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.4")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.9.5" || osVer == "10.10.5")
  {
    buildVer = get_kb_item("ssh/login/osx_build");
    if(buildVer)
    {
      if((osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F1134")) ||
         (osVer == "10.10.5" && version_is_less(version:buildVer, test_version:"14F1021")))
      {
        fix = "Apply patch from vendor";
        osVer = osVer + " Build " + buildVer;
      }
    }
  }
}

else if(osVer =~ "^10\.11" && version_is_less(version:osVer, test_version:"10.11.1")){
  fix = "10.11.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
