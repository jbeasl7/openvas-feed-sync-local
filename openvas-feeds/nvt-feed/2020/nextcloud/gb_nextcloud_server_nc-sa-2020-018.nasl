# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143884");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2020-05-13 07:46:09 +0000 (Wed, 13 May 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-19 19:15:00 +0000 (Mon, 19 Oct 2020)");

  script_cve_id("CVE-2020-8154");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 17.x < 17.0.5, 18.x < 18.0.3 Insecure Direct Object Reference Vulnerability (NC-SA-2020-018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an insecure direct object reference vulnerability
  due to a missing ownership check on remote wipe endpoint.");

  script_tag(name:"insight", value:"An Insecure direct object reference vulnerability in Nextcloud Server allows
  an attacker to remote wipe devices of other users when sending a malicious request directly to the endpoint.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Nextcloud server versions 17.x and 18.x.");

  script_tag(name:"solution", value:"Update to version 17.0.5, 18.0.3 or later.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2020-018");

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

if (version_in_range(version: version, test_version: "17.0.0", test_version2: "17.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "18.0.0", test_version2: "18.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
