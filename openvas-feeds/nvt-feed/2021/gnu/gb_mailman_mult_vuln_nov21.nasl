# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gnu:mailman";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147150");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-11-15 03:35:34 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-16 20:08:00 +0000 (Tue, 16 Nov 2021)");

  script_cve_id("CVE-2021-43331", "CVE-2021-43332");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mailman < 2.1.36 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("mailman_http_detect.nasl");
  script_mandatory_keys("gnu_mailman/detected");

  script_tag(name:"summary", value:"Mailman is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-43331: A crafted URL to the Cgi/options.py user options page can execute arbitrary
  JavaScript for XSS

  - CVE-2021-43332: The CSRF token for the Cgi/admindb.py admindb page contains an encrypted
  version of the list admin password. This could potentially be cracked by a moderator via an
  offline brute-force attack.");

  script_tag(name:"affected", value:"GNU Mailman prior to version 2.1.36.");

  script_tag(name:"solution", value:"Update to version 2.1.36 or later.");

  script_xref(name:"URL", value:"https://mail.python.org/archives/list/mailman-announce@python.org/message/I2X7PSFXIEPLM3UMKZMGOEO3UFYETGRL/");

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

if (version_is_less(version: version, test_version: "2.1.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.36", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
