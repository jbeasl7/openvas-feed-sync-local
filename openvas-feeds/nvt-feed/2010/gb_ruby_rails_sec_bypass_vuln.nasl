# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801653");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2010-3933");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_name("Ruby on Rails Security Bypass Vulnerability (Nov 2010)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl");
  script_mandatory_keys("rails/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41930");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1024624");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2719");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2010/10/15/security-vulnerability-in-nested-attributes-code-in-ruby-on-rails-2-3-9-and-3-0-0");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate arbitrary records.");

  script_tag(name:"affected", value:"Ruby on Rails versions 2.3.9 and 3.0.0.");

  script_tag(name:"insight", value:"The flaw is due to an input validation error when handling nested
  attributes, which can be exploited to manipulate arbitrary records by changing form input parameter names.");

  script_tag(name:"solution", value:"Update to version 2.3.10, 3.0.1 or later.");

  script_tag(name:"summary", value:"Ruby on Rails is prone to a security bypass vulnerability.");

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

if( version_is_equal( version: version, test_version: "2.3.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "3.0.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
