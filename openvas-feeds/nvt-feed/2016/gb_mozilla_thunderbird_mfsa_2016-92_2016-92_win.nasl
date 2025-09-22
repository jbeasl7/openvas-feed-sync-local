# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809828");
  script_version("2025-01-28T05:37:13+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-9079");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-28 05:37:13 +0000 (Tue, 28 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-27 21:55:53 +0000 (Mon, 27 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-12-01 13:38:43 +0530 (Thu, 01 Dec 2016)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2016-92, MFSA2016-92) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw exists due to:
  Use-after-free in SVG Animation.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to cause a denial of service via application crash,
  or execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird versions before 45.5.1.");

  script_tag(name:"solution", value:"Update to version 45.5.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-92");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94591");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"45.5.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"45.5.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
