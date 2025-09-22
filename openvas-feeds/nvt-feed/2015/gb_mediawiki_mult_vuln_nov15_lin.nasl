# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806626");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2015-8005", "CVE-2015-8004", "CVE-2015-8003", "CVE-2015-8002",
                "CVE-2015-8001");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-11-25 16:45:17 +0530 (Wed, 25 Nov 2015)");
  script_name("MediaWiki Multiple Vulnerabilities (Nov 2015) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-October/000181.html");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1034028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77378");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77375");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77374");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77372");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - the chunked upload API (ApiUpload) which does not restrict the uploaded data to the claimed file
  size.

  - an error in the application which does not throttle file uploads.

  - improper restrict access to revisions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct a
  denial of service (DoS) attack, gain privileged access and have some other unspecified impact.");

  script_tag(name:"affected", value:"MediaWiki versions prior to 1.23.11, 1.24.x prior to 1.24.4 and
  1.25.x prior to 1.25.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 1.23.11, 1.24.4, 1.25.3 or later.");

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

if(version_is_less(version:version, test_version:"1.23.11")) {
  fix = "1.23.11";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"1.24.0", test_version2:"1.24.3")) {
  fix = "1.24.4";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"1.25.0", test_version2:"1.25.3")) {
  fix = "1.25.3";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
