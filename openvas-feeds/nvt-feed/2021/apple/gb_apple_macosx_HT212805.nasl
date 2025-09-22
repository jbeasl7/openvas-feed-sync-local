# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818524");
  script_version("2024-02-09T14:47:30+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0340", "CVE-2020-29622", "CVE-2021-22925", "CVE-2021-30713",
                "CVE-2021-30783", "CVE-2021-30827", "CVE-2021-30828", "CVE-2021-30829",
                "CVE-2021-30830", "CVE-2021-30832", "CVE-2021-30835", "CVE-2021-30841",
                "CVE-2021-30842", "CVE-2021-30843", "CVE-2021-30844", "CVE-2021-30847",
                "CVE-2021-30850", "CVE-2021-30855", "CVE-2021-30857", "CVE-2021-30859",
                "CVE-2021-30860", "CVE-2021-30865", "CVE-2021-31010");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-22 19:37:00 +0000 (Fri, 22 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-09-14 18:07:04 +0530 (Tue, 14 Sep 2021)");
  script_name("Apple Mac OS X Security Update (HT212805)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information
  on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, disclose sensitive information and bypass
  security restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X 10.15.x prior to
  Security Update 2021-005 Catalina.");

  script_tag(name:"solution", value:"Apply Security Update 2021-005 for 10.15.x.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212805");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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
if(!osVer || osVer !~ "^10\.15\." || "Mac OS X" >!< osName){
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.15")
{
  if(version_in_range(version:osVer, test_version:"10.15", test_version2:"10.15.6")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.15.7")
  {
    if(version_is_less(version:buildVer, test_version:"19H1417"))
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
