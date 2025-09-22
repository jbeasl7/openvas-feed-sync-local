# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:givewp:givewp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133050");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-25 05:44:07 +0000 (Mon, 25 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-31 08:15:25 +0000 (Thu, 31 Jul 2025)");

  script_cve_id("CVE-2025-7205", "CVE-2025-7221");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GiveWP Plugin < 4.6.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/give/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'GiveWP' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-7205: Software is vulnerable to stored cross-site scripting via the donor notes
  parameter due to insufficient input sanitization and output escaping. This makes it possible for
  authenticated attackers, with GiveWP worker-level access and above, to inject arbitrary web
  scripts in pages that will execute whenever a user accesses an injected page. Additionally, they
  need to trick an administrator into visiting the legacy version of the site.

  - CVE-2025-7221: Software is vulnerable to unauthorized modification of data due to a missing
  capability check on the give_update_payment_status() function. This makes it possible for
  authenticated attackers, with GiveWP worker-level access and above, to update donations
  statuses. This ability is not present in the user interface.");

  script_tag(name:"affected", value:"WordPress GiveWP plugin prior to version 4.6.0.");

  script_tag(name:"solution", value:"Update to version 4.6.0 or later.");

  script_xref(name:"URL", value:"https://github.com/impress-org/givewp/blob/dc0510905208a7ae2024caa61117e2bb7ed7f5d7/readme.txt#L292");
  script_xref(name:"URL", value:"https://patchstack.com/database/wordpress/plugin/give/vulnerability/wordpress-givewp-plugin-4-6-1-pii-sensitive-data-exposure-vulnerability");

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

if( version_is_less( version: version, test_version: "4.6.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.6.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
