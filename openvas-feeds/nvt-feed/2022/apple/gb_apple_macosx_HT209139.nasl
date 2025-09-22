# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821282");
  script_version("2024-02-09T14:47:30+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-3194", "CVE-2015-5333", "CVE-2015-5334", "CVE-2016-0702",
                "CVE-2016-1777", "CVE-2017-12613", "CVE-2017-12618", "CVE-2017-5731",
                "CVE-2017-5732", "CVE-2017-5733", "CVE-2017-5734", "CVE-2017-5735",
                "CVE-2018-3639", "CVE-2018-3646", "CVE-2018-4126", "CVE-2018-4153",
                "CVE-2018-4203", "CVE-2018-4295", "CVE-2018-4296", "CVE-2018-4304",
                "CVE-2018-4308", "CVE-2018-4310", "CVE-2018-4321", "CVE-2018-4324",
                "CVE-2018-4326", "CVE-2018-4331", "CVE-2018-4332", "CVE-2018-4333",
                "CVE-2018-4334", "CVE-2018-4336", "CVE-2018-4337", "CVE-2018-4338",
                "CVE-2018-4340", "CVE-2018-4341", "CVE-2018-4343", "CVE-2018-4344",
                "CVE-2018-4346", "CVE-2018-4347", "CVE-2018-4348", "CVE-2018-4350",
                "CVE-2018-4351", "CVE-2018-4353", "CVE-2018-4354", "CVE-2018-4355",
                "CVE-2018-4383", "CVE-2018-4393", "CVE-2018-4395", "CVE-2018-4396",
                "CVE-2018-4399", "CVE-2018-4401", "CVE-2018-4406", "CVE-2018-4407",
                "CVE-2018-4408", "CVE-2018-4411", "CVE-2018-4412", "CVE-2018-4414",
                "CVE-2018-4417", "CVE-2018-4418", "CVE-2018-4425", "CVE-2018-4426",
                "CVE-2018-4433", "CVE-2018-4451", "CVE-2018-4456", "CVE-2018-5383",
                "CVE-2019-8643");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2022-08-04 16:15:17 +0530 (Thu, 04 Aug 2022)");
  script_name("Apple Mac OS X Security Update (HT209139)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple input validation errors.

  - Multiple memory corruption issues.

  - An improper state management.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, elevate privileges, disclose sensitive information
  and cause denial of service.");

  script_tag(name:"affected", value:"Apple Mac OS X versions prior to macOS Mojave 10.14.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.14 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209139");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit (0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || "Mac OS X" >!< osName)
  exit(0);

if(version_is_less(version:osVer, test_version:"10.14")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.14");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
