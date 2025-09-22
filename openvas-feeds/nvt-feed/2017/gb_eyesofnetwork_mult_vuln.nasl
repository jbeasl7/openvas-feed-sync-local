# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140346");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-09-04 13:33:34 +0700 (Mon, 04 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-23 15:06:00 +0000 (Tue, 23 Feb 2021)");

  script_cve_id("CVE-2017-13780", "CVE-2017-14118", "CVE-2017-14119", "CVE-2017-14753",
                "CVE-2017-14983", "CVE-2017-14984", "CVE-2017-14985", "CVE-2017-15188", "CVE-2017-15880");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Eyes Of Network (EON) < 5.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_consolidation.nasl");
  script_mandatory_keys("eyesofnetwork/detected");

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"EON is prone to the following vulnerabilities:

  - CVE-2017-13780: The EyesOfNetwork web interface (aka eonweb) allows directory traversal attacks
  for reading arbitrary files via the module/admin_conf/download.php file parameter.

  - CVE-2017-14118: In the EyesOfNetwork web interface (aka eonweb),
  module\tool_all\tools\interface.php does not properly restrict exec calls, which allows remote
  attackers to execute arbitrary commands via shell metacharacters in the host_list parameter to
  module/tool_all/select_tool.php.

  - CVE-2017-14119: In the EyesOfNetwork web interface (aka eonweb),
  module\tool_all\tools\snmpwalk.php does not properly restrict popen calls, which allows remote
  attackers to execute arbitrary commands via shell metacharacters in a parameter.

  - CVE-2017-15880: SQL injection vulnerability in the EyesOfNetwork web interface (aka eonweb)
  allows remote authenticated administrators to execute arbitrary SQL commands via the group_name
  parameter to module/admin_group/add_modify_group.php (for insert_group and update_group).

  - CVE-2017-14753, CVE-2017-14983, CVE-2017-14984, CVE-2017-14985, CVE-2017-15188: Multiple
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"EON versions 5.1 and below are vulnerable.");

  script_tag(name:"solution", value:"Update to version 5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://kk.whitecell-club.org/index.php/archives/220/");
  script_xref(name:"URL", value:"https://github.com/jsj730sos/cve/blob/master/Eonweb_module_admin_group_add_modify_group.php%20SQLi");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork:TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
