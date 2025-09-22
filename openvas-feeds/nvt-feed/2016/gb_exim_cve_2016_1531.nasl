# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105568");
  script_cve_id("CVE-2016-1531");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2024-01-10T05:05:17+0000");

  script_name("Exim < 4.86.2 Local Root / Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://www.exim.org/static/doc/CVE-2016-1531.txt");

  script_tag(name:"summary", value:"Exim is prone to a local root privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When Exim installation has been compiled with Perl support and
  contains a perl_startup configuration variable it can be exploited by malicious local attackers to
  gain root privileges.");

  script_tag(name:"solution", value:"Update to version 4.86.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-03-15 13:17:46 +0100 (Tue, 15 Mar 2016)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_family("SMTP problems");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"4.86.2" ) ) {
  report = report_fixed_ver(  installed_version:version, fixed_version:"4.86.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
