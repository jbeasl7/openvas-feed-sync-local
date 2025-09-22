# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wampserver:wampserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140891");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-03-27 11:28:57 +0700 (Tue, 27 Mar 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-10 11:29:00 +0000 (Mon, 10 Jun 2019)");

  script_cve_id("CVE-2018-8817");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WampServer < 3.1.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wampserver_detect.nasl");
  script_mandatory_keys("wampserver/installed");

  script_tag(name:"summary", value:"WampServer is prone to a cross-site request forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WampServer 3.1.2 and prior.");

  script_tag(name:"solution", value:"Update to version 3.1.3 or later.");

  script_xref(name:"URL", value:"http://forum.wampserver.com/read.php?2%2C138295%2C150722%2Cpage%3D6%23msg-150722");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
