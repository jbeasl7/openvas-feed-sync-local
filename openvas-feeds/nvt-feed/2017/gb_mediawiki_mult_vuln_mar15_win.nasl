# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108113");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2015-2931", "CVE-2015-2932", "CVE-2015-2933", "CVE-2015-2934",
                "CVE-2015-2935", "CVE-2015-2936", "CVE-2015-2937", "CVE-2015-2938",
                "CVE-2015-2941", "CVE-2015-2942");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-03-29 07:49:40 +0200 (Wed, 29 Mar 2017)");
  script_name("MediaWiki Multiple Vulnerabilities (Mar 2015) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-March/000175.html");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - incomplete blacklist vulnerability in includes/upload/UploadBase.php allows remote attackers to inject arbitrary web
  script or HTML via an application/xml MIME type for a nested SVG with a data: URI.

  - incomplete blacklist vulnerability allows remote attackers to inject arbitrary web script or HTML via an animated href XLink element.

  - MediaWiki does not properly handle when the Zend interpreter xml_parse function does not expand entities, which allows remote attackers
  to inject arbitrary web script or HTML via a crafted SVG file.

  - bypassing the SVG filtering and obtain sensitive user information via a mixed case @import in a style element in an SVG file.

  - when using HHVM or Zend PHP, allows remote attackers to cause a denial of service ('quadratic blowup' and memory consumption) via an XML file containing an
  entity declaration with long replacement text and many references to this entity, a different vulnerability than CVE-2015-2942.

  - Cross-site scripting (XSS) vulnerability allowing remote attackers to inject arbitrary web script or HTML via a custom JavaScript file, which is not properly
  handled when previewing the file.

  - Cross-site scripting (XSS) vulnerability, when using HHVM, allows remote attackers to inject arbitrary web script or HTML via an invalid parameter in a wddx
  format request to api.php, which is not properly handled in an error message, related to unsafe calls to wddx_serialize_value.

  - when using HHVM, allows remote attackers to cause a denial of service (CPU and memory consumption) via a large number of nested entity references in an (1) SVG
  file or (2) XMP metadata in a PDF file, aka a 'billion laughs attack', a different vulnerability than CVE-2015-2937.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct XSS attacks, gain access to sensitive information and
  have other some unspecified impact.");

  script_tag(name:"affected", value:"MediaWiki before 1.19.24, 1.2x before 1.23.9, and 1.24.x before 1.24.2");

  script_tag(name:"solution", value:"Upgrade to version 1.19.24 or 1.23.9
  or 1.24.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.19.24" ) ) {
  fix = "1.19.24";
  VULN = TRUE;
}

else if( version_in_range( version:vers, test_version:"1.20", test_version2:"1.23.8" ) ) {
  fix = "1.23.9";
  VULN = TRUE;
}

else if( version_in_range( version:vers, test_version:"1.24.0", test_version2:"1.24.1" ) ) {
  fix = "1.24.2";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
