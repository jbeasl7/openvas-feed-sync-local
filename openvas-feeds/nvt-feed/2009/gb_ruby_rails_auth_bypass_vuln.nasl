# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800912");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 17:44:31 +0000 (Tue, 13 Feb 2024)");
  script_cve_id("CVE-2009-2422");
  script_name("Ruby on Rails Authentication Bypass Vulnerability (Jun 2009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl");
  script_mandatory_keys("rails/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35702");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35579");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1802");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2009/6/3/security-problem-with-authenticate_with_http_digest");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass authentication by
  providing an invalid username with an empty password and gain unauthorized access to the system.");

  script_tag(name:"affected", value:"Ruby on Rails version 2.3.2 and prior.");

  script_tag(name:"insight", value:"This Flaw is caused During login process, the digest authentication functionality
  (http_authentication.rb) returns a 'nil' instead of 'false' when the provided
  username is not found and then proceeds to verify this value against the provided password.");

  script_tag(name:"solution", value:"Update to version 2.3.3 or later.");

  script_tag(name:"summary", value:"Ruby on Rails is prone to an authentication bypass vulnerability.");

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

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version:version, test_version:"2.3.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.3.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
