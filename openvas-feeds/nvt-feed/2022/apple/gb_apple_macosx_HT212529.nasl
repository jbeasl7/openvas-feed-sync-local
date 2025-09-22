# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826500");
  script_version("2024-02-09T14:47:30+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-36221", "CVE-2020-36222", "CVE-2020-36223", "CVE-2020-36224",
                "CVE-2020-36225", "CVE-2020-36226", "CVE-2020-36227", "CVE-2020-36228",
                "CVE-2020-36229", "CVE-2020-36230", "CVE-2021-21779", "CVE-2021-23841",
                "CVE-2021-30668", "CVE-2021-30669", "CVE-2021-30671", "CVE-2021-30672",
                "CVE-2021-30673", "CVE-2021-30676", "CVE-2021-30677", "CVE-2021-30678",
                "CVE-2021-30679", "CVE-2021-30680", "CVE-2021-30681", "CVE-2021-30682",
                "CVE-2021-30683", "CVE-2021-30684", "CVE-2021-30685", "CVE-2021-30686",
                "CVE-2021-30687", "CVE-2021-30688", "CVE-2021-30689", "CVE-2021-30691",
                "CVE-2021-30692", "CVE-2021-30693", "CVE-2021-30694", "CVE-2021-30695",
                "CVE-2021-30696", "CVE-2021-30697", "CVE-2021-30698", "CVE-2021-30700",
                "CVE-2021-30701", "CVE-2021-30702", "CVE-2021-30703", "CVE-2021-30704",
                "CVE-2021-30705", "CVE-2021-30706", "CVE-2021-30707", "CVE-2021-30708",
                "CVE-2021-30709", "CVE-2021-30710", "CVE-2021-30712", "CVE-2021-30713",
                "CVE-2021-30715", "CVE-2021-30716", "CVE-2021-30717", "CVE-2021-30718",
                "CVE-2021-30719", "CVE-2021-30720", "CVE-2021-30721", "CVE-2021-30722",
                "CVE-2021-30723", "CVE-2021-30724", "CVE-2021-30725", "CVE-2021-30726",
                "CVE-2021-30727", "CVE-2021-30728", "CVE-2021-30731", "CVE-2021-30733",
                "CVE-2021-30734", "CVE-2021-30735", "CVE-2021-30736", "CVE-2021-30737",
                "CVE-2021-30738", "CVE-2021-30739", "CVE-2021-30740", "CVE-2021-30744",
                "CVE-2021-30746", "CVE-2021-30749", "CVE-2021-30751", "CVE-2021-30753",
                "CVE-2021-30755", "CVE-2021-30756", "CVE-2021-30771");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-17 11:30:00 +0000 (Fri, 17 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-09-01 17:23:18 +0530 (Thu, 01 Sep 2022)");
  script_name("Apple Mac OS X Security Update (HT212529)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information
  on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass privacy preferences, execute arbitrary code and cause denial of service
  on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 11.x prior to 11.4");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 11.4 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212529");
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
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"11.4"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.4");
  security_message(data:report);
  exit(0);
}

exit(99);
