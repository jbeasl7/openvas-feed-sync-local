# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpliteadmin_project:phpliteadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106090");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2015-6517", "CVE-2015-6518");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-05-31 08:10:56 +0700 (Tue, 31 May 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpLiteAdmin < 1.9.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpliteadmin_detect.nasl");
  script_mandatory_keys("phpliteadmin/installed");

  script_tag(name:"summary", value:"phpLiteAdmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"phpLiteAdmin contains multiple vulnerabilities:

  - CVE-2015-6517: A cross-site request forgery (CSRF) vulnerability allows remote attackers to
  hijack the authentication of users for requests that drop database tables via the droptable
  parameter to phpliteadmin.php ().

  - CVE-2015-6518: Multiple cross-site scripting (XSS) vulnerabilities allow remote attackers to
  inject arbitrary web script or HTML via the PATH_INFO, droptable parameter, or table parameter to
  phpliteadmin.php.");

  script_tag(name:"impact", value:"A remote attacker may drop database tables or inject arbitrary
  web scripts or HTML code.");

  script_tag(name:"affected", value:"Version 1.9.6 and prior.");

  script_tag(name:"solution", value:"Update to version 1.9.7 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39714/");
  script_xref(name:"URL", value:"https://bitbucket.org/phpliteadmin/public/wiki/Changelog%20phpLiteAdmin%201.9.7");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.9.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
