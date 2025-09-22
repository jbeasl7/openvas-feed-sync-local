# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901185");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-0446");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Ruby on Rails < 2.3.11, 3.x < 3.0.4 Multiple XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl");
  script_mandatory_keys("rails/detected");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0343");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46291");
  script_xref(name:"URL", value:"http://groups.google.com/group/rubyonrails-security/msg/365b8a23b76a6b4a?dmode=source&output=gplain");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary web script
  or HTML via a crafted name or email value.");

  script_tag(name:"affected", value:"Ruby on Rails versions before 2.3.11, and 3.x before 3.0.4.");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error when processing 'name' or
  'email' values while the ':encode => :javascript' option is used, which could
  allow cross site scripting attacks.");

  script_tag(name:"solution", value:"Update to version 3.0.4, 2.3.11 or later.");

  script_tag(name:"summary", value:"Ruby on Rails is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.3.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0.0", test_version2: "3.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
