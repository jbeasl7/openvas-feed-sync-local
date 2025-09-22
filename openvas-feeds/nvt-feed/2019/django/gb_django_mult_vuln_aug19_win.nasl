# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112617");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-08-05 12:11:11 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-28 13:15:00 +0000 (Wed, 28 Aug 2019)");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-14232", "CVE-2019-14233", "CVE-2019-14234", "CVE-2019-14235");

  script_name("Django 1.11.x < 1.11.23, 2.1.x < 2.1.11, 2.2.x < 2.2.4 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-14232: Denial-of-service possibility in django.utils.text.Truncator

  - CVE-2019-14233: Denial-of-service possibility in strip_tags()

  - CVE-2019-14234: SQL injection possibility in key and index lookups for JSONField/HStoreField

  - CVE-2019-14235: Potential memory exhaustion in django.utils.encoding.uri_to_iri().");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the
  affected system or inject and execute malicious SQL queries.");

  script_tag(name:"affected", value:"Django versions 1.11.0 through 1.11.22, 2.1.0 through 2.1.10 and 2.2.0 through 2.2.3.");

  script_tag(name:"solution", value:"Update to version 1.11.23, 2.1.11 or 2.2.4 respectively.");

  script_xref(name:"URL", value:"https://groups.google.com/forum/#!topic/django-announce/jIoju2-KLDs");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2019/aug/01/security-releases/");

  exit(0);
}

CPE = "cpe:/a:djangoproject:django";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "1.11.0", test_version2: "1.11.22" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.11.23", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.1.0", test_version2: "2.1.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.11", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.2.0", test_version2: "2.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.4", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
