# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:op5:monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103905");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-02-11 12:56:33 +0100 (Tue, 11 Feb 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2013-6141");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("op5 Monitor < 6.1.3 Unspecified Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_op5_http_detect.nasl");
  script_mandatory_keys("op5/detected");

  script_tag(name:"summary", value:"op5 Monitor is prone to an unspecified information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified vulnerability in op5 Monitor before 6.1.3 allows
  attackers to read arbitrary files via unknown vectors related to lack of authorization.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  obtain sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"op5 Monitor versions prior to 6.1.3.");

  script_tag(name:"solution", value:"Update to version 6.1.3 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210122163841/http://www.securityfocus.com/bid/65244");
  script_xref(name:"URL", value:"https://bugs.op5.com/view.php?id=7677");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
