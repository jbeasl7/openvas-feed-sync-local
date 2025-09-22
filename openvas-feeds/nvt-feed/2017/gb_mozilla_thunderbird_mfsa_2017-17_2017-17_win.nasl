# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811186");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751",
                "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7756", "CVE-2017-7757",
                "CVE-2017-7778", "CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773",
                "CVE-2017-7774", "CVE-2017-7775", "CVE-2017-7776", "CVE-2017-7777",
                "CVE-2017-7758", "CVE-2017-7763", "CVE-2017-7764", "CVE-2017-7765",
                "CVE-2017-5470");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 14:24:00 +0000 (Fri, 03 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-06-15 19:01:05 +0530 (Thu, 15 Jun 2017)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2017-17, MFSA2017-17) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free using destroyed node when regenerating trees.

  - Use-after-free during docshell reloading.

  - Use-after-free with track elements.

  - Use-after-free with content viewer listeners.

  - Use-after-free with IME input.

  - Out-of-bounds read in WebGL with ImageInfo object.

  - Use-after-free and use-after-scope logging XHR header errors.

  - Use-after-free in IndexedDB.

  - Vulnerabilities in the Graphite 2 library.

  - Out-of-bounds read in Opus encoder.

  - Mac fonts render some unicode characters as spaces.

  - Domain spoofing with combination of Canadian Syllabics and other unicode blocks.

  - Mark of the Web bypass when saving executable files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, to delete arbitrary files by leveraging
  certain local file execution, to obtain sensitive information, and to cause
  a denial of service.");

  script_tag(name:"affected", value:"Mozilla Thunderbird versions before 52.2.");

  script_tag(name:"solution", value:"Update to version 52.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-17/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99040");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99057");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99041");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"52.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"52.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
