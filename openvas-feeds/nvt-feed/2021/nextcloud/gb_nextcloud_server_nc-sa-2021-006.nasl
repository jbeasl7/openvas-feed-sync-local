# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145516");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2021-03-08 04:05:34 +0000 (Mon, 08 Mar 2021)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-02 20:34:00 +0000 (Wed, 02 Dec 2020)");

  script_cve_id("CVE-2020-8152", "CVE-2020-8259", "CVE-2020-8296");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 20.0.0 Multiple Vulnerabilities (NC-SA-2020-040, NC-SA-2020-041, NC-SA-2021-006)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-8152: Insufficient protection of the server-side encryption keys allowed an attacker to
  replace the public key to decrypt them later on.

  - CVE-2020-8259: Insufficient protection of the server-side encryption keys allowed an attacker to
  replace the encryption keys.

  - CVE-2020-8296: A missing condition causes the external storage app to always store the users
  password in a recoverable format.");

  script_tag(name:"affected", value:"Nextcloud server prior to versions 20.0.0.");

  script_tag(name:"solution", value:"Update to version 20.0.0 or later.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2020-040");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2020-041");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2021-006");

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

if (version_is_less(version: version, test_version: "20.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
