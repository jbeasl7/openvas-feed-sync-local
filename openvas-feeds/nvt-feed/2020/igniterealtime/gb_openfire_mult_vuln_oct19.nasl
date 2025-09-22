# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:igniterealtime:openfire";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112713");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-03-19 11:21:11 +0000 (Thu, 19 Mar 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-20 12:20:00 +0000 (Fri, 20 Mar 2020)");

  script_cve_id("CVE-2019-20528", "CVE-2019-20525", "CVE-2019-20526", "CVE-2019-20527");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Openfire < 4.4.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openfire_http_detect.nasl");
  script_mandatory_keys("openfire/detected");

  script_tag(name:"summary", value:"Openfire is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-20525, CVE-2019-20526, CVE-2019-20527, CVE-2019-20528: XSS via various parameters in
  the setup/setup-datasource-standard.jsp

  - OF-1860: Admin Console - Plugin Upload vulnerable to ZipSlip

  - OF-1873: LDAP password disclosed on admin page

  - OF-1874: XSS on LDAP Server Settings page");

  script_tag(name:"impact", value:"Successful exploitation would allow a remote attacker to inject
  arbitrary script commands into the affected application, disclose information or write arbitrary
  files on the system, typically resulting in remote command execution.");

  script_tag(name:"affected", value:"Openfire version 4.4.1 and prior.");

  script_tag(name:"solution", value:"Update to version 4.4.2 or later.");

  script_xref(name:"URL", value:"https://www.netsparker.com/web-applications-advisories/ns-19-015-reflected-cross-site-scripting-in-openfire/");
  script_xref(name:"URL", value:"https://issues.igniterealtime.org/browse/OF-1860");
  script_xref(name:"URL", value:"https://issues.igniterealtime.org/browse/OF-1873");
  script_xref(name:"URL", value:"https://issues.igniterealtime.org/browse/OF-1874");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.4.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.4.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
