# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dell:emc_openmanage_server_administrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807564");
  script_version("2024-06-17T08:31:37+0000");
  script_tag(name:"last_modification", value:"2024-06-17 08:31:37 +0000 (Mon, 17 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:27:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-04-27 10:47:16 +0530 (Wed, 27 Apr 2016)");

  script_cve_id("CVE-2016-4004");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell OpenManage Server Administrator Directory Traversal Vulnerability (Apr 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dell_omsa_http_detect.nasl");
  script_mandatory_keys("dell/openmanage_server_administrator/detected");

  script_tag(name:"summary", value:"Dell OpenManage Server Administrator is prone to a directory
  traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation of user supplied
  input via 'file' parameter to ViewFile.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated
  administrators to read arbitrary files on the affected system.");

  script_tag(name:"affected", value:"Dell OpenManage Server Administrator version 8.4 and prior.");

  script_tag(name:"solution", value:"Update to version 8.5 or later.");

  script_xref(name:"URL", value:"https://dl.dell.com/topicspdf/omsa-oms-8-4-cve_rn_en-us.pdf");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39486");

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

if (version_is_less(version: version, test_version: "8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
