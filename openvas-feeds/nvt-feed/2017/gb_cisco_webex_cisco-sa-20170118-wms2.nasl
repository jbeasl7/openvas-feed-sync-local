# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:webex_meetings_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106531");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-19 11:43:50 +0700 (Thu, 19 Jan 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-26 01:29:00 +0000 (Wed, 26 Jul 2017)");

  script_cve_id("CVE-2017-3796");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Webex Meetings Server Command Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_webex_meetings_server_detect.nasl");
  script_mandatory_keys("cisco/webex/meetings_server/detected");

  script_tag(name:"summary", value:"A vulnerability in Cisco Webex Meetings Server could allow an authenticated,
  remote attacker to execute predetermined shell commands on other hosts.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient security configurations of bash in
  interactive mode. An attacker could exploit this vulnerability by connecting to a host as root and then
  connecting to another host via SSH and issuing predetermined shell commands.");

  script_tag(name:"impact", value:"A successful exploit could allow an attacker to execute commands as root on
  any other Cisco Webex Meeting Server host.");

  script_tag(name:"affected", value:"Cisco Webex Meetings Server version 2.6 and prior.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-wms2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
