# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:egroupware:egroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112075");
  script_version("2024-07-12T15:38:44+0000");
  script_tag(name:"last_modification", value:"2024-07-12 15:38:44 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-10-10 09:50:00 +0200 (Tue, 10 Oct 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-05 18:17:00 +0000 (Thu, 05 Oct 2017)");

  script_cve_id("CVE-2017-14920");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EGroupware Community Edition < 16.1.20170922 Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_egroupware_http_detect.nasl");
  script_mandatory_keys("egroupware/detected");

  script_tag(name:"summary", value:"EGroupware Community Edition is prone to a stored cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow an unauthenticated
  remote attacker to inject JavaScript via the User-Agent HTTP header.");

  script_tag(name:"affected", value:"EGroupware Community Edition prior to version
  16.1.20170922.");

  script_tag(name:"solution", value:"Update to version 16.1.20170922 or later.");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/09/28/12");
  script_xref(name:"URL", value:"https://github.com/EGroupware/egroupware/commit/0ececf8c78f1c3f9ba15465f53a682dd7d89529f");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"16.1.20170922" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.1.20170922", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
