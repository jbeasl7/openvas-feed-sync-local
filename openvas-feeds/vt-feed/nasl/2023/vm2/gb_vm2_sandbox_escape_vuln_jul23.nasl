# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vm2_project:vm2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170513");
  script_version("2026-05-07T06:32:13+0000");
  script_tag(name:"last_modification", value:"2026-05-07 06:32:13 +0000 (Thu, 07 May 2026)");
  script_tag(name:"creation_date", value:"2023-07-14 06:31:05 +0000 (Fri, 14 Jul 2023)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. Thus the original creation_date of the first VT has been kept.
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-01 14:05:45 +0000 (Thu, 01 Feb 2024)");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-37466");

  script_name("vm2 Sandbox Escape Vulnerability (GHSA-cchq-frgv-rjh5)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_javascript_packages_consolidation.nasl");
  script_mandatory_keys("javascript_package/vm2/detected");

  script_tag(name:"summary", value:"vm2 is prone to a sandbox escape vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Promise handler sanitization can be bypassed, allowing
  attackers to escape the sandbox and run arbitrary code.");

  script_tag(name:"impact", value:"Exploiting this vulnerability leads to remote code execution,
  assuming the attacker has arbitrary code execution primitive inside the context of vm2 sandbox.");

  script_tag(name:"affected", value:"vm2 prior to version 3.10.0.");

  script_tag(name:"solution", value:"Update to version 3.10.0 or later.

  Note: This is an incomplete fix by the vendor. CVE-2026-24120 for the remaining issue is covered
  by OID 1.3.6.1.4.1.25623.1.0.136831.");

  script_xref(name:"URL", value:"https://github.com/patriksimek/vm2/security/advisories/GHSA-cchq-frgv-rjh5");
  script_xref(name:"URL", value:"https://github.com/patriksimek/vm2/issues/533");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version:version, test_version:"3.10.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.10.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
