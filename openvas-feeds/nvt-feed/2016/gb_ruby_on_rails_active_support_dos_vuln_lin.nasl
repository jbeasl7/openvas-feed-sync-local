# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807384");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2015-3227");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-10-13 16:29:55 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Ruby on Rails Active Support DoS Vulnerability (Jun 2015) - Linux");

  script_tag(name:"summary", value:"Ruby on Rails is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Specially crafted XML
  documents can cause applications to raise a SystemStackError and potentially
  cause a denial of service attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause denial of service attack.");

  script_tag(name:"affected", value:"Ruby on Rails before 4.1.11 and
  Ruby on Rails 4.2.x before 4.2.2 on Linux.");

  script_tag(name:"solution", value:"Update to version 4.1.11, 4.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/06/16/16");
  script_xref(name:"URL", value:"https://groups.google.com/forum/message/raw?msg=rubyonrails-security/bahr2JLnxvk/x4EocXnHPp8J");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_rails_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("rails/detected", "Host/runs_unixoide");
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

VULN = FALSE;

if( version_is_less( version: version, test_version: "4.1.11" ) )
{
  fix = "4.1.11";
  VULN = TRUE;
}

else if( version =~ "^(4\.2)" )
{
  if( version_is_less( version: version, test_version: "4.2.2" ) )
  {
    fix = "4.2.2";
    VULN = TRUE;
  }
}

if( VULN )
{
  report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
