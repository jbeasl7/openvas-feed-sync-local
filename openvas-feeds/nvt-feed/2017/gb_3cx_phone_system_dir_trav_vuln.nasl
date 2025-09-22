# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:3cx:3cx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140437");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-18 15:51:00 +0700 (Wed, 18 Oct 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-13 17:42:00 +0000 (Mon, 13 Nov 2017)");

  script_cve_id("CVE-2017-15359");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("3CX Phone System < 15.5 Update 2 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_3cx_phone_system_consolidation.nasl");
  script_mandatory_keys("3cx/phone_system/detected");

  script_tag(name:"summary", value:"3CX Phone System is prone to a directory traversal attack where
  an authenticated attacker may read arbitrary files.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"3CX Phone System version 15.5.3849.1 and prior.");

  script_tag(name:"solution", value:"Update 3CX Phone System to version 15.5 Update 2 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42991/");
  script_xref(name:"URL", value:"https://www.3cx.com/blog/releases/pbx-update/");
  script_xref(name:"URL", value:"https://www.3cx.com/blog/change-log/phone-system-change-log/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "15.5.3849.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.5 Update 2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
