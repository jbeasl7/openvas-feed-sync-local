# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trendmicro:smart_protection_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811916");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-11395");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-10-24 12:42:06 +0530 (Tue, 24 Oct 2017)");

  script_name("Trend Micro Smart Protection Server Command Injection Vulnerability");

  script_tag(name:"summary", value:"Trend Micro Smart Protection Server is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exits due to the cm_agent.php script
  did not sanitize input parameters before executing a system command.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers with authenticated access to execute arbitrary code on vulnerable
  installations.");

  script_tag(name:"affected", value:"Trend Micro Smart Protection Server (Standalone) 3.1 and 3.2");

  script_tag(name:"solution", value:"Upgrade to Trend Micro Smart Protection Server 3.2-1085 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1117933");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100461");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_trendmicro_smart_protection_server_detect.nasl");
  script_mandatory_keys("trendmicro/sps/detected");

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

build = get_kb_item("trendmicro/sps/build");

if (version == "3.1") {
  report = report_fixed_ver(installed_version: version, installed_build: build,
                            fixed_version: "3.2", fixed_build: "1085", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version == "3.2") {
  if (!build || version_is_less(version: build, test_version: "1085")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "3.2", fixed_build: "1085", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
