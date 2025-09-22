# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807377");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2016-6317");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-08 15:16:00 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"creation_date", value:"2016-10-13 14:29:34 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Ruby on Rails Active Record SQL Injection Vulnerability (Aug 2016) - Windows");

  script_tag(name:"summary", value:"Ruby on Rails is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the way Active Record
  interprets parameters in combination with the way that JSON parameters are
  parsed, it is possible for an attacker to issue unexpected database queries
  with 'IS NULL' or empty where clauses.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to bypass intended database-query restrictions and perform NULL checks
  or trigger missing WHERE clauses via a crafted request, as demonstrated by
  certain '[nil]' values.");

  script_tag(name:"affected", value:"Ruby on Rails 4.2.x before 4.2.7.1 on Windows");

  script_tag(name:"solution", value:"Update to version 4.2.7.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/08/11/4");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92434");
  script_xref(name:"URL", value:"https://groups.google.com/forum/#!topic/ruby-security-ann/WccgKSKiPZA");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2016/8/11/Rails-5-0-0-1-4-2-7-2-and-3-2-22-3-have-been-released");
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

if( version_in_range( version: version, test_version: "4.2.0", test_version2: "4.2.7.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.7.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
