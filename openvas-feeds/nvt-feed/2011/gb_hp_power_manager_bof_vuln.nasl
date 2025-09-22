# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:power_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801569");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-4113");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Power Manager Login Form Buffer Overflow Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("hp_power_manager_detect.nasl");
  script_mandatory_keys("hp_power_manager/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow users to cause a Denial of Service
condition.");

  script_tag(name:"affected", value:"HP Power Manager (HPPM) before 4.3.2");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing URL parameters passed to
the login form of the management web server. It can be exploited to cause a stack-based buffer overflow via a
specially crafted 'Login' variable.");

  script_tag(name:"solution", value:"Upgrade to HP Power Manager (HPPM) 4.3.2 or later.");

  script_tag(name:"summary", value:"HP Power Manager is prone to a buffer overflow vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42644");
  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=129251322532373&w=2");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-292/");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Dec/1024902.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
