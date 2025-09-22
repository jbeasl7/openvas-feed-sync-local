# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801765");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_cve_id("CVE-2011-3187");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Ruby on Rails Logfile Injection Vulnerability (Mar 2011)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl");
  script_mandatory_keys("rails/detected");

  script_xref(name:"URL", value:"https://gist.github.com/868268");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46423");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Mar/162");
  script_xref(name:"URL", value:"http://webservsec.blogspot.com/2011/02/ruby-on-rails-vulnerability.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary
  data into the affected HTTP header field, attackers may be able to launch cross-site request-forgery,
  cross-site scripting, HTML-injection, and other attacks.");

  script_tag(name:"affected", value:"Ruby on Rails version 3.0.5.");

  script_tag(name:"insight", value:"The flaw is due to input validation error for the
  'X-Forwarded-For' field in the header.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Ruby on Rails is prone to a file injection vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"WillNotFix");

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

if( version_is_equal( version:version, test_version:"3.0.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"Will Not Fix", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
