# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834700");
  script_version("2025-02-19T05:37:55+0000");
  script_cve_id("CVE-2024-9936");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-10-17 11:40:39 +0530 (Thu, 17 Oct 2024)");
  script_name("Mozilla Firefox Security Update (MFSA2024-53) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to an unspecified
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an undefined
  behavior in selection node cache.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to trigger unexpected behavior, which may lead to an exploitable crash.");

  script_tag(name:"affected", value:"Mozilla Firefox prior to version 131.0.3 on
  Mac OS X.");

  script_tag(name:"solution", value:"Update to version 131.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-53/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"131.0.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"131.0.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
