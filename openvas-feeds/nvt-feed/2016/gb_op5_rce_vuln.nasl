# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:op5:monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106380");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-11-07 12:46:37 +0700 (Mon, 07 Nov 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-34115");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OP5 Monitor <= 7.1.9 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_op5_http_detect.nasl");
  script_mandatory_keys("op5/detected");

  script_tag(name:"summary", value:"OP5 Monitor is prone to a remote command execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OP5 Monitor has a CSRF entry point that can be used to execute
  arbitrary remote commands on op5 system sent via HTTP GET requests, allowing attackers to
  completely takeover the affected host, to be victimized a user must be authenticated and visit a
  malicious webpage or click an infected link.");

  script_tag(name:"impact", value:"An authenticated attacker execute arbitrary commands.");

  script_tag(name:"affected", value:"OP5 Monitor versions 7.1.9 and prior.");

  script_tag(name:"solution", value:"Update to version 7.2.0 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39676/");
  script_xref(name:"URL", value:"https://www.op5.com/blog/news/op5-monitor-7-2-0-release-notes/");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/op5-monitor-authenticated-command-execution");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "7.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
