# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836542");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2025-8027", "CVE-2025-8028", "CVE-2025-8029", "CVE-2025-8030",
                "CVE-2025-8031", "CVE-2025-8032", "CVE-2025-8033", "CVE-2025-8034",
                "CVE-2025-8035");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-24 09:05:50 +0530 (Thu, 24 Jul 2025)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2025-58) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution, disclose information and conduct denial of service
  attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version 120.x before
  128.13 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 128.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-58/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range_exclusive(version:vers, test_version_lo:"120.0", test_version_up:"128.13")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"128.13", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);