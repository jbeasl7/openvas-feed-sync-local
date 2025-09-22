# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106606");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-02-17 10:06:51 +0700 (Fri, 17 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-23 02:29:00 +0000 (Thu, 23 Nov 2017)");

  script_cve_id("CVE-2016-10089");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_http_detect.nasl");
  script_mandatory_keys("nagios/detected");

  script_tag(name:"summary", value:"Nagios is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The init script for Nagios calls 'chown' on a path under the control of
Nagios. CVE-2016-8641 describes an attack wherein that restricted user replaces the aforementioned path with a
symlink. An identical attack not addressed by CVE-2016-8641 works with hardlinks.");

  script_tag(name:"impact", value:"A local attacker may gain root privileges.");

  script_tag(name:"affected", value:"Nagios before 4.3.3 (4.x.x).");

  script_tag(name:"solution", value:"Update to Nagios 4.3.3 or a later version.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95171");
  script_xref(name:"URL", value:"https://github.com/NagiosEnterprises/nagioscore/blob/nagios-4.3.3/daemon-init.in");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
