# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112252");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-04-09 12:25:00 +0200 (Mon, 09 Apr 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 21:19:00 +0000 (Wed, 08 Nov 2023)");

  script_cve_id("CVE-2018-9284");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR-868L StarHub Firmware RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-868L devices are prone to a pre-authenticated remote
  code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability is an unauthenticated buffer overflow that
  occurs when the affected router parses authentication requests.");

  script_tag(name:"impact", value:"Upon successful exploitation, an attacker could then run arbitrary
  code under the privilege of a web service.");

  script_tag(name:"affected", value:"D-Link DIR-868L with customized Singapore StarHub firmware.");

  script_tag(name:"solution", value:"Upgrade to version 1.21SHCb03 or later.");

  script_xref(name:"URL", value:"http://www.dlink.com.sg/dir-868l/#firmware");
  script_xref(name:"URL", value:"https://www.fortinet.com/blog/threat-research/fortiguard-labs-discovers-vulnerability-in--d-link-router-dir868.html");

  exit(0);
}

CPE = "cpe:/o:dlink:dir-868l_firmware";

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if ("shc" >< version && version_is_less(version: version, test_version: "1.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.21SHCb03");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
