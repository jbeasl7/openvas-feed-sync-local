# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805662");
  script_version("2023-09-15T16:10:33+0000");
  script_tag(name:"last_modification", value:"2023-09-15 16:10:33 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2015-06-19 12:17:48 +0530 (Fri, 19 Jun 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-0344", "CVE-2015-0343");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe Connect < 9.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_http_detect.nasl");
  script_mandatory_keys("adobe/connect/detected");

  script_tag(name:"summary", value:"Adobe Connect is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to multiple cross-site scripting (XSS)
  vulnerabilities in the web application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary html or script code via the query parameter and some unspecified vectors.");

  script_tag(name:"affected", value:"Adobe Connect prior to version 9.4.");

  script_tag(name:"solution", value:"Update to version 9.4 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Jun/61");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75188");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75153");
  script_xref(name:"URL", value:"https://helpx.adobe.com/adobe-connect/release-note/connect-94-release-notes.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
