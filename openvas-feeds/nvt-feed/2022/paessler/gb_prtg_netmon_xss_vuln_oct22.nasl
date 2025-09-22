# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:paessler:prtg_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126191");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-10-28 12:35:36 +0000 (Fri, 28 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-28 19:51:00 +0000 (Fri, 28 Oct 2022)");

  script_cve_id("CVE-2022-35739");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PRTG Network Monitor < 23.1.83.1742 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_prtg_network_monitor_detect.nasl");
  script_mandatory_keys("prtg_network_monitor/installed");

  script_tag(name:"summary", value:"PRTG Network Monitor is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PRTG Network Monitor does not prevent custom input for a
  device's icon, which can be modified to insert arbitrary content into the style tag for that
  device.");

  script_tag(name:"affected", value:"PRTG Network Monitor prior to version 23.1.83.1742.");

  script_tag(name:"solution", value:"Update to version 23.1.83.1742 or later.");

  script_xref(name:"URL", value:"https://kb.paessler.com/en/topic/91149-what-do-i-need-to-know-about-cve-2022-35739");
  script_xref(name:"URL", value:"https://www.paessler.com/prtg/history/preview#23.1.83.1742");
  script_xref(name:"URL", value:"https://raxis.com/blog/cve-2022-35739");

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

if (version_is_less(version: version, test_version: "23.1.83.1742")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.1.83.1742", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
