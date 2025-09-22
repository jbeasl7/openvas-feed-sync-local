# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807605");
  script_version("2023-07-21T05:05:22+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-0960", "CVE-2016-0961", "CVE-2016-0962", "CVE-2016-0963",
                "CVE-2016-0986", "CVE-2016-0987", "CVE-2016-0988", "CVE-2016-0989",
                "CVE-2016-0990", "CVE-2016-0991", "CVE-2016-0992", "CVE-2016-0993",
                "CVE-2016-0994", "CVE-2016-0995", "CVE-2016-0996", "CVE-2016-0997",
                "CVE-2016-0998", "CVE-2016-0999", "CVE-2016-1000", "CVE-2016-1001",
                "CVE-2016-1002", "CVE-2016-1005", "CVE-2016-1010");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-14 19:19:00 +0000 (Wed, 14 Dec 2022)");
  script_tag(name:"creation_date", value:"2016-03-11 13:41:11 +0530 (Fri, 11 Mar 2016)");
  script_name("Adobe Air Security Update (APSB16-08) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Air is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - integer overflow vulnerabilities

  - use-after-free vulnerabilities

  - a heap overflow vulnerability

  - memory corruption vulnerabilities");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability will allow remote
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Air version before 21.0.0.176.");

  script_tag(name:"solution", value:"Update to version 21.0.0.176 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-08.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"21.0.0.176")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"21.0.0.176");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);