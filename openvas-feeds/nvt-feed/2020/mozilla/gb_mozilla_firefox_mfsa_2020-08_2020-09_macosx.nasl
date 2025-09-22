# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816701");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6808",
                "CVE-2020-6809", "CVE-2020-6810", "CVE-2020-6811", "CVE-2019-20503",
                "CVE-2020-6812", "CVE-2020-6813", "CVE-2020-6814", "CVE-2020-6815");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-22 20:15:00 +0000 (Wed, 22 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-12 10:42:26 +0530 (Thu, 12 Mar 2020)");
  script_name("Mozilla Firefox Security Advisories (MFSA2020-08, MFSA2020-09) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A use-after-free issue when removing data about origins.

  - Multiple out-of-bounds read issues.

  - A use-after-free in cubeb during stream destruction.

  - A URL Spoofing issue via javascript.

  - Memory safety bugs.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers
  to execute arbitrary code, gain access to sensitive information, escalate
  privileges and cause denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox versions before 74.");

  script_tag(name:"solution", value:"Update to version 74 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-08/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"74")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"74", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
