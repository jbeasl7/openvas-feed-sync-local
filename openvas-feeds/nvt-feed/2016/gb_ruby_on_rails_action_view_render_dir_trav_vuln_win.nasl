# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809354");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2016-2097");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-08 15:43:00 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"creation_date", value:"2016-10-14 20:09:25 +0530 (Fri, 14 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Ruby on Rails Action View 'render' Directory Traversal Vulnerability (Feb 2016) - Windows");

  script_tag(name:"summary", value:"Ruby on Rails is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of
  crafted requests to action view, one of the components of action pack.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files by leveraging an application's unrestricted
  use of the render method.");

  script_tag(name:"affected", value:"Ruby on Rails versions before 3.2.22.2 and 4.x before 4.1.14.2
  on Windows.");

  script_tag(name:"solution", value:"Update to version 3.2.22.2, 4.1.14.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3509");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83726");
  script_xref(name:"URL", value:"https://groups.google.com/g/rubyonrails-security/c/ddY6HgqB2z4/m/we0RasMZIAAJ");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("rails/detected", "Host/runs_windows");
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

if( version_is_less( version: version, test_version: "3.2.22.2" ) ) {
  fix = "3.2.22.2";
  VULN = TRUE;
}

else if( version =~ "^4\." ) {
  if( version_is_less( version: version, test_version: "4.1.14.2" ) ) {
    fix = "4.1.14.2";
    VULN = TRUE;
  }
}

if( VULN ) {
  report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
