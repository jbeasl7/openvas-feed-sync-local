# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sudo_project:sudo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117186");
  script_version("2025-07-15T05:43:27+0000");
  script_cve_id("CVE-2021-3156");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-15 05:43:27 +0000 (Tue, 15 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-01-27 06:47:49 +0000 (Wed, 27 Jan 2021)");
  script_name("Sudo Heap-Based Buffer Overflow Vulnerability (Baron Samedit) - Version Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_sudo_ssh_login_detect.nasl");
  script_mandatory_keys("sudo/ssh-login/detected");

  script_xref(name:"URL", value:"https://www.sudo.ws/releases/stable/#1.9.5p2");
  script_xref(name:"URL", value:"https://www.sudo.ws/releases/legacy/#1.8.32");
  script_xref(name:"URL", value:"https://www.sudo.ws/security/advisories/unescape_overflow/");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"Sudo is prone to a heap-based buffer overflow vulnerability
  dubbed 'Baron Samedit'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Sudo is allowing privilege escalation to root via 'sudoedit -s'
  and a command-line argument that ends with a single backslash character.");

  script_tag(name:"affected", value:"Sudo versions 1.7.7 through 1.7.10p9, 1.8.2 through 1.8.31p2
  and 1.9.0 through 1.9.5p1 in their default configuration.");

  script_tag(name:"solution", value:"Update to version 1.8.32, 1.9.5p2 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"1.7.7", test_version2:"1.7.10p9" ) ||
    version_in_range( version:vers, test_version:"1.8.2", test_version2:"1.8.31p2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.32", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version_in_range( version:vers, test_version:"1.9.0", test_version2:"1.9.5p1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.9.5p2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
