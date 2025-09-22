# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806635");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2014-7199");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-11-26 17:50:31 +0530 (Thu, 26 Nov 2015)");
  script_name("MediaWiki < 1.19.19, 1.22.x < 1.22.11, 1.23.x < 1.23.4 'SVG File' XSS Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-September/000161.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70153");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in CSS filtering in SVG
  files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary web script or HTML via a crafted SVG file.");

  script_tag(name:"affected", value:"MediaWiki versions prior to 1.19.19, 1.22.x prior to 1.22.11
  and 1.23.x prior to 1.23.4 on Linux.");

  script_tag(name:"solution", value:"Update to version 1.19.19, 1.22.11, 1.23.4 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"1.19.19")) {
  fix = "1.19.19";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"1.22.0", test_version2:"1.22.10")) {
  fix = "1.22.11";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"1.23.0", test_version2:"1.23.3")) {
  fix = "1.23.4";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
