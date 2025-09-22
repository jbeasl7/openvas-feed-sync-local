# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112142");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-11-28 08:41:00 +0100 (Tue, 28 Nov 2017)");

  script_cve_id("CVE-2017-15051", "CVE-2017-15052", "CVE-2017-15053", "CVE-2017-15054",
                "CVE-2017-15055", "CVE-2017-15278");

  script_name("TeamPass < 2.1.27.9 Multiple Vulnerabilities (Nov 2017)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_http_detect.nasl");
  script_mandatory_keys("teampass/detected");

  script_tag(name:"summary", value:"TeamPass is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - CVE-2017-15051: Multiple stored cross-site scripting (XSS) vulnerabilities via the (1) URL value
  of an item or (2) user log history.

  - CVE-2017-15052: No proper access control on users.queries.php.

  - CVE-2017-15053: No proper access control on roles.queries.php.

  - CVE-2017-15054: Arbitrary file upload.

  - CVE-2017-15055: No proper access control on items.queries.php.

  - CVE-2017-15278: Cross-Site Scripting (XSS) due to insufficient filtration of data
  (in /sources/folders.queries.php).");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site,
  upload malicious code as an authenticated user or modify/delete any arbitrary roles within the
  application.");

  script_tag(name:"affected", value:"TeamPass version 2.1.27.8 and prior.");

  script_tag(name:"solution", value:"Update to version 2.1.27.9 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://blog.amossys.fr/teampass-multiple-cve-01.html");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/releases/tag/2.1.27.9");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/blob/master/changelog.md");

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

if( version_is_less( version:vers, test_version:"2.1.27.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.1.27.9", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
