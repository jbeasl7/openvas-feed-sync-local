# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805601");
  script_version("2025-02-17T05:38:47+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-1130", "CVE-2015-1131", "CVE-2015-1132", "CVE-2015-1133",
                "CVE-2015-1134", "CVE-2015-1135", "CVE-2015-1136", "CVE-2015-1088",
                "CVE-2015-1089", "CVE-2015-1091", "CVE-2015-1093", "CVE-2015-1137",
                "CVE-2015-1138", "CVE-2015-1139", "CVE-2015-1140", "CVE-2015-1141",
                "CVE-2015-1142", "CVE-2015-1143", "CVE-2015-1144", "CVE-2015-1145",
                "CVE-2015-1146", "CVE-2015-1147", "CVE-2015-1148", "CVE-2015-1095",
                "CVE-2015-1098", "CVE-2015-1099", "CVE-2015-1100", "CVE-2015-1101",
                "CVE-2015-1102", "CVE-2015-1103", "CVE-2015-1104", "CVE-2015-1105",
                "CVE-2015-1117", "CVE-2015-1118");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-17 05:38:47 +0000 (Mon, 17 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-14 16:20:08 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"creation_date", value:"2015-04-24 15:41:40 +0530 (Fri, 24 Apr 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 (Apr 2015)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist. Please see the
  references for more details.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to execute arbitrary code with system privilege, man-in-the-middle
  attack, remote attacker to bypass network filters, to cause a denial of
  service, a context-dependent attacker to corrupt memory and cause a denial of
  service, bypass signature validation or potentially execute arbitrary code, a
  local application to gain elevated privileges by using a compromised service
  and some unspecified impacts.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.8 through
  10.8.5, 10.9 through 10.9.5, and 10.10.x through 10.10.2");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version 10.10.3
  or later or apply security update 2015-004 for 10.8 and 10.9 versions. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/kb/HT204659");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73982");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73984");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72328");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73981");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.([89]|10)");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.([89]|10)" || "Mac OS X" >!< osName){
  exit(0);
}

if((osVer == "10.8.5") || (osVer == "10.9.5"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }

  if(osVer == "10.8.5" && version_is_less(version:buildVer, test_version:"12F2518"))
  {
    fix = "Apply Security Update 2015-004";
    osVer = osVer + " Build " + buildVer;
  }

  else if(osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F1077"))
  {
    fix = "Apply Security Update 2015-004";
    osVer = osVer + " Build " + buildVer;
  }
}

if(osVer =~ "^10\.8")
{
  if(version_is_less(version:osVer, test_version:"10.8.5")){
    fix = "Upgrade to latest OS release 10.8.5 and apply patch from vendor";
  }
}
else if(osVer =~ "^10\.9")
{
  if(version_is_less(version:osVer, test_version:"10.9.5")){
    fix = "Upgrade to latest OS release 10.9.5 and apply patch from vendor";
  }
}

else if(osVer =~ "^10\.10")
{
  if(version_is_less(version:osVer, test_version:"10.10.3")){
    fix = "10.10.3";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
