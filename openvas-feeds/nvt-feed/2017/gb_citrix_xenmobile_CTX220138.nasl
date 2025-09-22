# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:xenmobile_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106887");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-06-20 15:46:37 +0700 (Tue, 20 Jun 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-07 01:29:00 +0000 (Fri, 07 Jul 2017)");

  script_cve_id("CVE-2017-9231");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix XenMobile XXE Vulnerability (CTX220138)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_citrix_xenmobile_http_detect.nasl");
  script_mandatory_keys("citrix/endpoint_management/detected");

  script_tag(name:"summary", value:"An XML external entity (XXE) processing vulnerability has been
  identified in Citrix XenMobile Server that could allow an unauthenticated attacker to retrieve
  potentially sensitive information from the server.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Citrix XenMobile Server 9.x and 10.x.");

  script_tag(name:"solution", value:"Update to version 10.5 Rolling Patch 3 or later.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX220138");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.5.0.10038")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.0.10038");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
