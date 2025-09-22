# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807557");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-3172", "CVE-2016-3659");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 03:09:00 +0000 (Thu, 01 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-04-25 18:08:07 +0530 (Mon, 25 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cacti Multiple SQL Injection Vulnerabilities -01 (Apr 2016) - Windows");

  script_tag(name:"summary", value:"Cacti is prone to multiple SQL injection
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An insufficient validation of user supplied input passed via HTTP GET parameter 'parent_id' to tree.php
script.

  - An insufficient validation of user supplied input passed via HTTP POST parameter 'host_group_data' to
graph_view.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary SQL
commands.");

  script_tag(name:"affected", value:"Cacti versions 0.8.8g and earlier on Windows.");

  script_tag(name:"solution", value:"Update to 0.8.8h or a higher version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2673");
  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2667");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136547");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/03/10/13");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cacti_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version:version, test_version:"0.8.8g")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"0.8.8h");
  security_message(data:report, port:port);
  exit(0);
}

exit(0);
