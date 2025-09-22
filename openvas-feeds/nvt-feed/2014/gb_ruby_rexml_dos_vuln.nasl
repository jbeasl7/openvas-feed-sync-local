# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ruby-lang:ruby";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804889");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2014-8080");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-11-21 16:58:24 +0530 (Fri, 21 Nov 2014)");
  script_name("Ruby 'REXML' parser DoS Vulnerability (Nov 2014) - Windows");

  script_tag(name:"summary", value:"Ruby is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to an incorrectly configured
  XML parser accepting XML external entities from an untrusted source.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service (crash) condition.");

  script_tag(name:"affected", value:"Ruby versions Ruby 1.9.x before 1.9.3-p550,
  2.0.x before 2.0.0-p594, and 2.1.x before 2.1.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 1.9.3-p550, 2.0.0-p594, 2.1.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61607");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70935");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2014/10/27/rexml-dos-cve-2014-8080");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ruby_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ruby/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.9.0.0", test_version2:"1.9.3.p549") ||
   version_in_range(version:version, test_version:"2.0.0.0", test_version2:"2.0.0.p593") ||
   version_in_range(version:version, test_version:"2.1.0.0", test_version2:"2.1.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.9.3-p550 / 2.0.0-p594 / 2.1.4", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
