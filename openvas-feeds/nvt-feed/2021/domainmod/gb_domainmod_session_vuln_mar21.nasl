# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:domainmod:domainmod";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.145583");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2021-03-16 02:43:09 +0000 (Tue, 16 Mar 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-18 19:28:00 +0000 (Thu, 18 Mar 2021)");

  script_cve_id("CVE-2020-35358");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DomainMOD < 4.18.0 Session Expiration Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_domainmod_http_detect.nasl");
  script_mandatory_keys("domainmod/detected");

  script_tag(name:"summary", value:"DomainMOD is prone to a session expiration vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On changing a password, both sessions using the changed
  password and old sessions in any other browser or device do not expire and remain active.");

  script_tag(name:"impact", value:"If attacker steals the password and logs in from different
  place, as other sessions is not destroyed, the attacker will be still logged in the account even
  after password gets reset by a valid user. This will cause the unauthorised session being still
  active and malicious actor can takeover the complete access to they account until that session
  expires.");

  script_tag(name:"affected", value:"DomainMOD version 4.17.0 and prior.");

  script_tag(name:"solution", value:"Update to version 4.18.0 or later.");

  script_xref(name:"URL", value:"https://gist.github.com/anku-agar/0fec2ffd98308e550ce9b5d4b395d0d7");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "4.17.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.18.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
