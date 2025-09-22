# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:nodebb:nodebb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111101");
  script_version("2025-01-30T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-01-30 05:38:01 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-05-07 16:00:00 +0200 (Sat, 07 May 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-28 17:06:00 +0000 (Thu, 28 Sep 2017)");

  script_cve_id("CVE-2015-3295", "CVE-2015-3296");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # markdown plugin might be disabled

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NodeBB < 0.7.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_nodebb_http_detect.nasl");
  script_mandatory_keys("nodebb/detected");

  script_tag(name:"summary", value:"NodeBB is prone to a stored cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting this vulnerability may allow an attacker to perform
  cross-site scripting attacks on unsuspecting users in the context of the affected website. As a
  result, the attacker may be able to steal cookie-based authentication credentials and to launch
  other attacks.");

  script_tag(name:"affected", value:"NodeBB prior to version 0.7.0.");

  script_tag(name:"solution", value:"Update to version 0.7.0 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71824");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q2/94");

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

if (version_is_less(version: version, test_version: "0.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.7.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
