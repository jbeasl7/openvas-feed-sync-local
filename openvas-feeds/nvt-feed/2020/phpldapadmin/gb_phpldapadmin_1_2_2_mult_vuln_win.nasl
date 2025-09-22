# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpldapadmin_project:phpldapadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117014");
  script_version("2024-12-24T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-24 05:05:31 +0000 (Tue, 24 Dec 2024)");
  script_tag(name:"creation_date", value:"2020-11-06 10:48:39 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:25:00 +0000 (Mon, 16 Nov 2020)");

  script_cve_id("CVE-2012-0834", "CVE-2018-12689");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpLDAPadmin <= 1.2.2 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpldapadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpldapadmin/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"phpLDAPadmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2012-0834: Cross-site scripting (XSS) in lib/QueryRender.php

  - CVE-2018-12689: LDAP injection via a crafted server_id parameter in a cmd.php?cmd=login_form
  request, or a crafted username and password in the login panel");

  script_tag(name:"affected", value:"phpLDAPadmin version 1.2.2 and prior.");

  script_tag(name:"solution", value:"Update to version 1.2.3 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2012/02/02/9");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44926/");

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

if (version_is_less_equal(version: version, test_version: "1.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
