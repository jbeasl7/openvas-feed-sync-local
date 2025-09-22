# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:imp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100826");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-09-28 17:11:37 +0200 (Tue, 28 Sep 2010)");
  script_cve_id("CVE-2010-3695", "CVE-2010-4778");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Horde IMP Webmail 'fetchmailprefs.php' HTML Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("imp_detect.nasl");
  script_mandatory_keys("horde/imp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43515");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/513992");

  script_tag(name:"summary", value:"Horde IMP Webmail is prone to an HTML injection vulnerability
  because it fails to sufficiently sanitize user-supplied data before it is used in dynamic
  content.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attacker-supplied HTML or JavaScript code could run in the
  context of the affected site, potentially allowing the attacker to steal cookie-based
  authentication credentials and to control how the site is rendered to the user. Other attacks are
  also possible.");

  script_tag(name:"affected", value:"Horde IMP 4.3.7 is affected. Other versions may also be
  vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! info = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = info["version"];
path = info["location"];

if( version_is_less_equal( version:vers, test_version:"4.3.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.3.8", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
