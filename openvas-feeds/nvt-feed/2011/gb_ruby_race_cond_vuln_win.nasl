# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ruby-lang:ruby";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801759");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-1004");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_name("Ruby 'FileUtils.remove_entry_secure()' Method Race Condition Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43434");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46460");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=678913");
  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2011/02/18/fileutils-is-vulnerable-to-symlink-race-attacks/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ruby_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ruby/detected", "Host/runs_windows");

  script_tag(name:"insight", value:"The flaw is due to a race condition within the
  'FileUtils.remove_entry_secure' method, which can be exploited to delete
  arbitrary directories and files via symlink attacks.");

  script_tag(name:"solution", value:"Update to version 1.8.7-334, 1.9.1-p431, 1.9.2-p180 or later.");

  script_tag(name:"summary", value:"Ruby is prone to race condition vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code with
  elevated privileges or cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Ruby version 1.8.6 through 1.8.6 patchlevel 420

  Ruby version 1.8.7 through 1.8.7 patchlevel 330

  Ruby version 1.9.1 through 1.9.1 patchlevel 430

  Ruby version 1.9.2 through 1.9.2 patchlevel 136

  Ruby version 1.9.3dev, 1.8.8dev");

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
    version_in_range( version: version, test_version: "1.8.7", test_version2: "1.8.7.330" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.7-p334", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version:"1.9.1", test_version2:"1.9.1.430" ) ||
    version_is_equal( version: version, test_version: "1.8.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.9.1-p431", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version:"1.9.2", test_version2:"1.9.2.136" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.9.2-p180", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
