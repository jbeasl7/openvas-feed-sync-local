# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bigtreecms:bigtree_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124149");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-08-31 06:24:35 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-09 19:39:00 +0000 (Tue, 09 Aug 2022)");

  script_cve_id("CVE-2022-36197");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("BigTree CMS <= 4.4.16 File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_mandatory_keys("bigtree_cms/detected");

  script_tag(name:"summary", value:"BigTree CMS is prone to an arbitrary file upload
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"BigTree CMS was discovered to contain an arbitrary file upload
  vulnerability which allows attackers to execute arbitrary code via a crafted PDF file.");

  script_tag(name:"affected", value:"BigTree CMS version 4.4.16 and prior had been reported as
  vulnerable.");

  script_tag(name:"solution", value:"No solution is required.

  Note: The vendor rejects the assumption, that the application is vulnerable. Instead it is mentioned,
  that the reported issue is with the used Webbrowser.");

  script_xref(name:"URL", value:"https://github.com/bigtreecms/BigTree-CMS/issues/392");

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

report = report_fixed_ver(installed_version: version, fixed_version: "Not vulnerable", install_path: location);
security_message(port: port, data: report);

exit(0);
