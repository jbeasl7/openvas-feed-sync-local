# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:concrete5:concrete5";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108152");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-05-08 09:03:26 +0200 (Mon, 08 May 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-22 13:38:00 +0000 (Wed, 22 Mar 2017)");
  script_cve_id("CVE-2017-6908", "CVE-2017-6905");
  script_name("Concrete5 <= 5.6.3.4 Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_concrete5_detect.nasl");
  script_mandatory_keys("concrete5/installed");

  script_tag(name:"summary", value:"Concrete5 is prone to multiple cross-site scripting vulnerabilities because it
  fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code in the browser
  of an unsuspecting user in the context of the affected site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Concrete5 versions up to and including 5.6.3.4.");

  script_tag(name:"solution", value:"Update to version 5.6.3.5 or later.");

  script_xref(name:"URL", value:"https://github.com/concrete5/concrete5-legacy/issues/1948");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96891");
  script_xref(name:"URL", value:"https://www.concrete5.org/about/blog/community-blog/legacy-concrete5-version-5635-now-available-version-82-coming-next-week");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"5.6.3.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.6.3.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
