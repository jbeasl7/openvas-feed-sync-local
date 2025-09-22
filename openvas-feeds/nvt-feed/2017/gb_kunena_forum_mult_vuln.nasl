# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kunena:kunena";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108107");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-9103", "CVE-2014-9102");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-23 09:57:33 +0100 (Thu, 23 Mar 2017)");
  script_name("Joomla Kunena Forum Extension < 3.0.6 Multiple Vulnerabilities");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_kunena_forum_detect.nasl");
  script_mandatory_keys("kunena_forum/installed");

  script_tag(name:"summary", value:"The Kunena Forum Extension for Joomla is prone to multiple
  vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - multiple SQL injection vulnerabilities

  - multiple cross-site scripting (XSS) vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successfully exploitation will allow a remote attacker to:

  - execute arbitrary script code in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based authentication credentials and to
  launch other attacks.

  - compromise the application, access or modify data, or exploit latent vulnerabilities in the
  underlying database.");

  script_tag(name:"affected", value:"Joomla Kunena Forum Extension versions before 3.0.6.");

  script_tag(name:"solution", value:"Update to version 3.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"3.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.6" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );