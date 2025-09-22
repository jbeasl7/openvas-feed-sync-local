# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836466");
  script_version("2025-06-26T05:40:52+0000");
  script_cve_id("CVE-2025-6424", "CVE-2025-6425");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-06-26 05:40:52 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-25 12:19:14 +0530 (Wed, 25 Jun 2025)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2025-52) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution, disclose information and conduct denial of service
  attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR prior to version
  115.25 on Windows.");

  script_tag(name:"solution", value:"Update to version 115.25 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-52/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.25")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.25", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);