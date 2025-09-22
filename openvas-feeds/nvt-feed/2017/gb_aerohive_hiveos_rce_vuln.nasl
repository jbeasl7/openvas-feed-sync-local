# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:aerohive:hiveos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106876");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-06-16 12:18:01 +0700 (Fri, 16 Jun 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Aerohive Networks HiveOS RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_aerohive_hiveos_detect.nasl");
  script_mandatory_keys("aerohive_hiveos/detected");

  script_tag(name:"summary", value:"Aerohive HiveOS is prone to a remote command execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"With a local file inclusion it is possible to poison /var/log/messages
with PHP code which allows an attacker to e.g. change the root password.");

  script_tag(name:"affected", value:"HiveOS 5.1r5 until 6.1r4.");

  script_tag(name:"solution", value:"Update to version 6.1r5 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42178/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "5.1r5", test_version2: "6.1r4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1r5");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
