# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:op5:monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103557");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-08-30 11:27:11 +0200 (Thu, 30 Aug 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");
  script_name("op5 Monitor < 5.4.2, 5.5.x <= 5.7.3 Unspecified SQLi Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_op5_http_detect.nasl");
  script_mandatory_keys("op5/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210123161424/http://www.securityfocus.com/bid/55255");

  script_tag(name:"summary", value:"op5 Monitor is prone to an unspecified SQL injection (SQLi)
  vulnerability because it fails to sufficiently sanitize user-supplied data before using it in an
  SQL query.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"affected", value:"op5 Monitor versions through 5.4.2 and 5.5.x through 5.7.3 are
  known to be affected.");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed in a beta version. Please
  contact the vendor for more information.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.4.2") ||
    version_in_range(version: version, test_version: "5.5.0", test_version2: "5.7.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port:port, data: report);
  exit(0);
}

exit(99);
