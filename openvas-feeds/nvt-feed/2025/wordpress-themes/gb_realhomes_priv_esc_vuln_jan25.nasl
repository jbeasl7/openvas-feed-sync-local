# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:inspirythemes:realhomes";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171110");
  script_version("2025-02-07T05:37:57+0000");
  script_tag(name:"last_modification", value:"2025-02-07 05:37:57 +0000 (Fri, 07 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-01-24 08:20:50 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2024-32444", "CVE-2024-32555");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("WordPress InspiryThemes RealHomes Theme Multiple Privilege Escalation Vulnerabilities (Jan 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_wordpress_themes_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/realhomes/detected");

  script_tag(name:"summary", value:"The WordPress theme RealHomes by InspiryThemes is prone to
  multiple privilege escalation vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-32444: This vulnerability occurs because the code that handles user input doesn't have
  any authorization or nonce check. If registration is enabled on the settingd any attacker can
  takeover the website. The theme also doesn't check if the user is calling the
  inspiry_ajax_register action with a $user_role parameter and has permission to create
  Administrator role accounts, allowing anyone to generate one.

  - CVE-2024-32555: Unauthenticated privilege escalation via the social login.");

  script_tag(name:"impact", value:"These vulnerabilities allow any unauthenticated user to increase
  their privileges and take over the WordPress site by performing a series of HTTP requests.");

  script_tag(name:"affected", value:"All versions of WordPress theme RealHomes by InspiryThemes.");

  script_tag(name:"solution", value:"No known solution is available as of 06th February, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.bleepingcomputer.com/news/security/critical-zero-days-impact-premium-wordpress-real-estate-plugins/");
  script_xref(name:"URL", value:"https://patchstack.com/articles/unauthenticated-privilege-escalation-vulnerability-patched-in-real-home-theme/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
security_message( port: port, data: report );
exit( 0 );
