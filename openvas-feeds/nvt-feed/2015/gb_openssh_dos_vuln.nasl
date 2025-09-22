# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806048");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-6565");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-10 14:36:41 +0530 (Thu, 10 Sep 2015)");
  script_name("OpenSSH Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://www.openssh.com/txt/release-7.0");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75990");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/08/22/1");

  script_tag(name:"summary", value:"OpenSSH is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to sshd uses world-writable
  permissions for TTY devices.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users
  to cause a denial of service (terminal disruption) or possibly have unspecified
  other impact.");

  script_tag(name:"affected", value:"OpenSSH versions 6.8 and 6.9.");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 7.0 or later.");

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

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"6.8", test_version2:"6.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.0", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );