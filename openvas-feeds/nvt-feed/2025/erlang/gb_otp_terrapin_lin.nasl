# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:erlang:erlang%2fotp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105346");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-25 11:58:37 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 03:15:00 +0000 (Fri, 29 Dec 2023)");
  script_cve_id("CVE-2023-48795");
  script_name("Erlang/OTP (Erlang OTP) Prefix Truncation Attacks in SSH Specification (Terrapin Attack) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_erlang_otp_ssh_banner_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("erlang/otp/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://github.com/erlang/otp/releases/tag/OTP-26.2.1");
  script_xref(name:"URL", value:"https://github.com/erlang/otp/releases/tag/OTP-25.3.2.8");
  script_xref(name:"URL", value:"https://github.com/erlang/otp/releases/tag/OTP-24.3.4.15");
  script_xref(name:"URL", value:"https://github.com/erlang/otp/releases/tag/OTP-23.3.4.20");
  script_xref(name:"URL", value:"https://github.com/erlang/otp/releases/tag/OTP-22.3.4.27");
  script_xref(name:"URL", value:"https://terrapin-attack.com");

  script_tag(name:"summary", value:"Erlang/OTP (Erlang OTP) is vulnerable to a novel prefix
  truncation attack (a.k.a. Terrapin attack) in the SSH component.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Parts of the SSH specification are vulnerable to a novel prefix
  truncation attack (a.k.a. Terrapin attack), which allows a man-in-the-middle attacker to strip an
  arbitrary number of messages right after the initial key exchange, breaking SSH extension
  negotiation (RFC8308) in the process and thus downgrading connection security.");

  script_tag(name:"affected", value:"Erlang/OTP (Erlang OTP) versions prior to 22.3.4.27, 23.x prior
  to 23.3.4.20, 24.x prior to 24.3.4.15, 25.x prior to 25.3.2.8 and 26.x prior to 26.2.1.");

  script_tag(name:"solution", value:"Update to version 22.3.4.27, 23.3.4.20, 24.3.4.15, 25.3.2.8,
  26.2.1 or later.

  Notes:

  - Client and Server implementations need to run a fixed version to mitigate this flaw

  - Please create an override for this result if an adequate mitigation (e.g. in form of disabling
  the affected ciphers) has been applied and the risk is accepted that the mitigation won't be
  reverted again in the future");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"22.3.4.27" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"22.3.4.27", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"23.0", test_version_up:"23.3.4.20" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"23.3.4.20", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"24.0", test_version_up:"24.3.4.15" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"24.3.4.15", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"25.0", test_version_up:"25.3.2.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"25.3.2.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"26.0", test_version_up:"26.2.5.11" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"26.2.5.11", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
