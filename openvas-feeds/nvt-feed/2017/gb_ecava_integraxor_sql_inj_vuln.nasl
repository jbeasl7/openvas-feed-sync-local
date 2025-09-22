# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ecava:integraxor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106607");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2017-02-17 10:06:51 +0700 (Fri, 17 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-01 23:45:00 +0000 (Wed, 01 Mar 2017)");

  script_cve_id("CVE-2016-8341");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ECAVA IntegraXor <= 5.0.413.0 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ecava_integraxor_http_detect.nasl");
  script_mandatory_keys("ecava/integraxor/detected");

  script_tag(name:"summary", value:"ECAVA IntegraXor is prone to a SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The ECAVA IntegraXor web server has parameters that are
  vulnerable to SQL injection. If the queries are not sanitized, the host's database could be
  subject to read, write, and delete commands.");

  script_tag(name:"impact", value:"A successful exploit of this vulnerability could lead to
  arbitrary data leakage, data manipulation, and remote code execution.");

  script_tag(name:"affected", value:"ECAVA IntegraXor version 5.0.413.0 and prior.");

  script_tag(name:"solution", value:"Update to version 5.2.722.2 or later.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-031-02");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95907");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.0.413.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.722.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
