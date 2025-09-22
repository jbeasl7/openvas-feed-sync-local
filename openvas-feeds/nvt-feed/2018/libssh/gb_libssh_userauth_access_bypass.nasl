# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libssh:libssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108473");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-10-17 08:58:02 +0200 (Wed, 17 Oct 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");
  script_cve_id("CVE-2018-10933");
  script_name("libssh Server 'CVE-2018-10933' Authentication Bypass");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_libssh_server_detect.nasl");
  script_mandatory_keys("libssh/server/detected");

  script_xref(name:"URL", value:"https://www.libssh.org/security/advisories/CVE-2018-10933.txt");

  script_tag(name:"summary", value:"The remote SSH server is using libssh which is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By presenting the server an SSH2_MSG_USERAUTH_SUCCESS message in place of the
  SSH2_MSG_USERAUTH_REQUEST message which the server would expect to initiate authentication the server is authenticating
  users without any credentials.

  NOTE: Some server implementations using libssh (e.g. Github Enterprise) are not affected by this issue.");

  script_tag(name:"impact", value:"An attacker could successfully authenticate without any credentials.");

  script_tag(name:"affected", value:"libssh versions starting from 0.6 and prior to 0.7.6/0.8.4.");

  script_tag(name:"solution", value:"Update to libssh version 0.7.6, 0.8.4 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"0.6", test_version2:"0.7.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.7.6" );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:vers, test_version:"0.8", test_version2:"0.8.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.8.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );