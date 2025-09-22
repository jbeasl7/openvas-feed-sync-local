# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902536");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-1335");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Cybozu Office 6.x < 8.1.1 Address Book and User List XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/office/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44992");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48446");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN55508059/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000047.html");

  script_tag(name:"summary", value:"Cybozu Office is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of unspecified input
  related to the address book and user list functions, which allows attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers execute
  arbitrary HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Cybozu Office versions 6, 7, and 8 before 8.1.1.");

  script_tag(name:"solution", value:"Update to version 8.1.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"6.0.0", test_version2:"8.1.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.1.1", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
