# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:linksys:e5600_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128083");
  script_version("2025-01-29T05:37:24+0000");
  script_tag(name:"last_modification", value:"2025-01-29 05:37:24 +0000 (Wed, 29 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-24 13:10:13 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2024-57536", "CVE-2024-57537", "CVE-2024-57538", "CVE-2024-57539",
                "CVE-2024-57540", "CVE-2024-57541", "CVE-2024-57542", "CVE-2024-57543",
                "CVE-2024-57544", "CVE-2024-57545");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Linksys E5600 Router <= 1.2.00.360516 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_linksys_devices_consolidation.nasl");
  script_mandatory_keys("linksys/detected");

  script_tag(name:"summary", value:"Linksys E8450 routers are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-57536: Command injection vulnerability via wizard_status

  - CVE-2024-57537, CVE-2024-57538, CVE-2024-57540, CVE-2024-57541, CVE-2024-57543, CVE-2024-57544,
    CVE-2024-57545: Buffer overflow vulnerability

  - CVE-2024-57539: Command injection vulnerability via userEmail

  - CVE-2024-57542: Command injection vulnerability via field id_email_check_btn");

  script_tag(name:"affected", value:"Linksys E5600 routers with firmware versions 1.1.0.26 and
  prior.");

  script_tag(name:"solution", value:"No known solution is available as of 28th January, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/Wood1314/Linksys_E8450_vul/blob/main/8/8.md");
  script_xref(name:"URL", value:"https://github.com/Wood1314/Linksys_E8450_vul/blob/main/1/1.md");
  script_xref(name:"URL", value:"https://github.com/Wood1314/Linksys_E8450_vul/blob/main/10/10.md");
  script_xref(name:"URL", value:"https://github.com/Wood1314/Linksys_E8450_vul/blob/main/3/3.md");
  script_xref(name:"URL", value:"https://github.com/Wood1314/Linksys_E8450_vul/blob/main/2/2.md");
  script_xref(name:"URL", value:"https://github.com/Wood1314/Linksys_E8450_vul/blob/main/9/9.md");
  script_xref(name:"URL", value:"https://github.com/Wood1314/Linksys_E8450_vul/blob/main/4/4.md");
  script_xref(name:"URL", value:"https://github.com/Wood1314/Linksys_E8450_vul/blob/main/7/7.md");
  script_xref(name:"URL", value:"https://github.com/Wood1314/Linksys_E8450_vul/blob/main/6/6.md");
  script_xref(name:"URL", value:"https://github.com/Wood1314/Linksys_E8450_vul/blob/main/5/5.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"1.2.00.360516" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
