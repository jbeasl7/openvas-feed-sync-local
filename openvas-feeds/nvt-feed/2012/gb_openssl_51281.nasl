# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103394");
  script_cve_id("CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2012-0027");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_version("2023-07-25T05:05:58+0000");

  script_name("OpenSSL < 0.9.8s, 1.0.x < 1.0.0f Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51281");
  script_xref(name:"URL", value:"http://www.openssl.org/news/secadv_20120104.txt");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-01-20 11:28:16 +0100 (Fri, 20 Jan 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_openssl_consolidation.nasl");
  script_mandatory_keys("openssl/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple security vulnerabilities.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to obtain sensitive
  information, cause a denial-of-service condition and perform unauthorized actions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.0\." && version_is_less(version:vers, test_version:"1.0.0f")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.0f", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(vers =~ "^0\.9\." && version_is_less(version:vers, test_version:"0.9.8s")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.8s", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
