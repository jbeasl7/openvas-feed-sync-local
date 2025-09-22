# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phusion:passenger";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106765");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-04-19 16:11:47 +0200 (Wed, 19 Apr 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-24 21:26:00 +0000 (Mon, 24 Apr 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_cve_id("CVE-2016-10345");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Phusion Passenger File Overwrite Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phusion_passenger_detect.nasl");
  script_mandatory_keys("phusion_passenger/installed");

  script_tag(name:"summary", value:"Phusion Passenger is prone to a /tmp file overwrite vulnerability which
could allow local attackers to gain the privileges of the passenger user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"With access to the system, a user could plant a symlink in /tmp that
resulted in a chosen-file overwrite attempt whenever passenger-install-nginx-module was run, using the access
rights of the executing user, potentially even with chosen content.");

  script_tag(name:"impact", value:"A local attacker may gain privileges of the passenger user.");

  script_tag(name:"affected", value:"Phusion Passenger before version 5.1.0.");

  script_tag(name:"solution", value:"Upgrade to version 5.1.0 or later.");

  script_xref(name:"URL", value:"https://github.com/phusion/passenger/commit/e5b4b0824d6b648525b4bf63d9fa37e5beeae441");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
