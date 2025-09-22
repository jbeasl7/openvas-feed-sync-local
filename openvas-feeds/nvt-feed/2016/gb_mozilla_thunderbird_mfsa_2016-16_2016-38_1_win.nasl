# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808695");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792",
                "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796",
                "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800",
                "CVE-2016-2801", "CVE-2016-2802", "CVE-2016-1979", "CVE-2016-1950",
                "CVE-2016-1974", "CVE-2016-1953", "CVE-2016-1964", "CVE-2016-1961",
                "CVE-2016-1960", "CVE-2016-1957", "CVE-2016-1956", "CVE-2016-1955",
                "CVE-2016-1954", "CVE-2016-1952");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-09-07 11:44:05 +0530 (Wed, 07 Sep 2016)");
  script_name("Mozilla Thunderbird Security Advisories - 1 - (MFSA2016-16, MFSA2016-38) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist. Please see the references for more information.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird versions before 45.");

  script_tag(name:"solution", value:"Update to version 45 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-37/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84222");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84221");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84223");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84219");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84218");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-36/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-35/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-34/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-27/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-24/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-23/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-20/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-19/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-18/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-17/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-16/");

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

if(version_is_less(version:vers, test_version:"45")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"45", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
