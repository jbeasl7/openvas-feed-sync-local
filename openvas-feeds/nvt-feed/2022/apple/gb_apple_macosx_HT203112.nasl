# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826504");
  script_version("2025-07-25T05:44:05+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-4364", "CVE-2014-4426", "CVE-2013-6438", "CVE-2014-0098",
                "CVE-2014-4427", "CVE-2014-6271", "CVE-2014-7169", "CVE-2014-4428",
                "CVE-2014-4425", "CVE-2014-4430", "CVE-2014-3537", "CVE-2014-4431",
                "CVE-2014-4432", "CVE-2014-4435", "CVE-2014-4373", "CVE-2014-4405",
                "CVE-2014-4404", "CVE-2014-4436", "CVE-2014-4380", "CVE-2014-4407",
                "CVE-2014-4388", "CVE-2014-4418", "CVE-2014-4371", "CVE-2014-4419",
                "CVE-2014-4420", "CVE-2014-4421", "CVE-2014-4433", "CVE-2014-4434",
                "CVE-2014-4375", "CVE-2011-2391", "CVE-2014-4408", "CVE-2014-4442",
                "CVE-2014-4422", "CVE-2014-4437", "CVE-2014-4438", "CVE-2014-4439",
                "CVE-2014-4440", "CVE-2014-4441", "CVE-2014-4351", "CVE-2013-5150",
                "CVE-2014-4417", "CVE-2014-3566", "CVE-2014-4443", "CVE-2014-4444",
                "CVE-2014-4391");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-01 21:38:00 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"creation_date", value:"2022-09-02 11:24:06 +0530 (Fri, 02 Sep 2022)");
  script_name("Apple Mac OS X Security Update (HT203112)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, cause denial of service and disclose sensitive
  information on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X versions prior to 10.10.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.10 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT203112");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || "Mac OS X" >!< osName)
  exit(0);

if(version_is_less(version:osVer, test_version:"10.10")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.10");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
