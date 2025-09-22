# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:op5:monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103556");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-08-30 10:46:24 +0200 (Thu, 30 Aug 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("op5 Monitor <= 5.4.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_op5_http_detect.nasl");
  script_mandatory_keys("op5/detected");

  script_tag(name:"summary", value:"op5 Monitor is prone to an HTML injection vulnerability and an
  SQL injection (SQLi) vulnerability because it fails to sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting these issues may allow an attacker to compromise the
  application, access or modify data, exploit vulnerabilities in the underlying database, execute
  HTML and script code in the context of the affected site, steal cookie-based authentication
  credentials, or control how the site is rendered to the user, other attacks are also possible.");

  script_tag(name:"affected", value:"op5 Monitor version 5.4.2 is known to be vulnerable. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210123172850/https://www.securityfocus.com/bid/55191/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version:version, test_version: "5.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
