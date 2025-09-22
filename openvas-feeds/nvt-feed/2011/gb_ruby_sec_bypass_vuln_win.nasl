# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ruby-lang:ruby";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801760");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-1005");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Ruby '#to_s' Security Bypass Vulnerability (Feb 2011)");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=678920");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46458");
  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2011/02/18/exception-methods-can-bypass-safe/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ruby_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ruby/detected", "Host/runs_windows");

  script_tag(name:"insight", value:"The flaw is due to the error in 'Exception#to_s' method, which trick
  safe level mechanism and destructively modifies an untaitned string to be tainted.");

  script_tag(name:"solution", value:"Update to version 1.8.7-334 or later.");

  script_tag(name:"summary", value:"Ruby is prone to a security bypass vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to bypass certain security
  restrictions and perform unauthorized actions.");

  script_tag(name:"affected", value:"Ruby version 1.8.6 through 1.8.6 patchlevel 420

  Ruby version 1.8.7 through 1.8.7 patchlevel 330

  Ruby version 1.8.8dev");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://rubyforge.org/frs/?group_id=167");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "1.8.6", test_version2: "1.8.6.420" ) ||
    version_in_range( version: version, test_version: "1.8.7", test_version2: "1.8.7.330" ) ||
    version_is_equal( version: version, test_version: "1.8.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.7-p334", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
