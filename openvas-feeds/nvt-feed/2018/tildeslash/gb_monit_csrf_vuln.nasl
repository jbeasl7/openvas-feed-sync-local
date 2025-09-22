# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tildeslash:monit";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141468");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-09-11 11:29:46 +0700 (Tue, 11 Sep 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2016-7067");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Monit < 5.20.0 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_monit_detect.nasl");
  script_mandatory_keys("monit/detected");

  script_tag(name:"summary", value:"Monit is vulnerable to a cross-site request forgery (CSRF)
  attack. Successful exploitation will enable an attacker to disable/enable all monitoring for a
  particular host or disable/enable monitoring for a specific service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Monit version 5.19.0 and prior.");

  script_tag(name:"solution", value:"Update to version 5.20.0 or later.");

  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2016/q4/267");
  script_xref(name:"URL", value:"https://mmonit.com/monit/changes/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.20.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.20.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
