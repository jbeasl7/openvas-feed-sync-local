# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:couchdb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100572");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2010-0009");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CouchDB < 0.11 Message Digest Verification Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_apache_couchdb_http_detect.nasl");
  script_mandatory_keys("apache/couchdb/detected");

  script_tag(name:"summary", value:"CouchDB is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CouchDB compares message digests using a variable time
  algorithm.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows an attacker to determine
  if a forged digest is partially correct. Repeated attacks will allow them to determine specific,
  legitimate digests.");

  script_tag(name:"affected", value:"CouchDB prior to version 0.11.");

  script_tag(name:"solution", value:"Update to version 0.11 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39116");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"0.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.11", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
