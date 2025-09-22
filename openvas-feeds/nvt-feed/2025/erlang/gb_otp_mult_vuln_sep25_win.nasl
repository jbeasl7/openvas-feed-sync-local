# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:erlang:erlang%2fotp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119098");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-11 14:22:32 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2025-48038", "CVE-2025-48039", "CVE-2025-48040", "CVE-2025-48041");
  script_name("Erlang/OTP (Erlang OTP) Multiple Vulnerabilities (Sep 2025) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_erlang_otp_ssh_banner_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("erlang/otp/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://github.com/erlang/otp/security/advisories/GHSA-pvj7-9652-7h9r");
  script_xref(name:"URL", value:"https://github.com/erlang/otp/security/advisories/GHSA-rr5p-6856-j7h8");
  script_xref(name:"URL", value:"https://github.com/erlang/otp/security/advisories/GHSA-h7rg-6rjg-4cph");
  script_xref(name:"URL", value:"https://github.com/erlang/otp/security/advisories/GHSA-79c4-cvv7-4qm3");

  script_tag(name:"summary", value:"Erlang/OTP (Erlang OTP) is prone to multiple vulnerabilities in
  the SSH component.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-48038: SSH Unverified File Handles can Cause Excessive Use of System Resources

  - CVE-2025-48039: SSH Unverified Paths can Cause Excessive Use of System Resources

  - CVE-2025-48040: SSH Malicious Key Exchange Messages may Lead to Excessive Resource Consumption

  - CVE-2025-48041: SSH_FXP_OPENDIR may Lead to Exhaustion of File Handles");

  script_tag(name:"affected", value:"Erlang/OTP (Erlang OTP) versions prior to 26.2.5.15, 27.x prior
  to 27.3.4.3 and 28.x prior to 28.0.3.

  Note: While the advisories initially stating versions >= 17.0 are affected they are also including
  the following note:

  > In the case of this vulnerability, versions prior to OTP 17.0 are likely also affected.");

  script_tag(name:"solution", value:"Update to version 26.2.5.15, 27.3.4.3, 28.0.3 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
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

if( version_is_less( version:version, test_version:"26.2.5.15" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"26.2.5.15", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"27.0", test_version_up:"27.3.4.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"27.3.4.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"28.0", test_version_up:"28.0.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"28.0.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
