# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_mq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808620");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2016-0260", "CVE-2016-0259", "CVE-2015-7473");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-30 15:44:00 +0000 (Thu, 30 Jun 2016)");
  script_tag(name:"creation_date", value:"2016-07-25 10:52:32 +0530 (Mon, 25 Jul 2016)");

  script_name("IBM WebSphere MQ Multiple Vulnerabilities (Jul 2016)");

  script_tag(name:"summary", value:"IBM WebSphere MQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An improper access control for some local MQSC commands.

  - An improper access control for some display commands in local runmqsc.

  - The heap storage allocated on an error path is not deallocated by queue manager agents.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local user
  with authority to connect to the local queue manager to obtain sensitive
  information, remote attackers to cause a denial of service and also allow a
  local attacker with certain permissions to execute commands against the local
  queue manager that they should not have access to.");

  script_tag(name:"affected", value:"IBM WebSphere MQ version 8.0.0.0 through 8.0.0.4.");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere MQ version 8.0.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21984555");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91060");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91064");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91041");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21984561");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21984564");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ibm_websphere_mq_consolidation.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range(version:version, test_version:"8.0.0.0", test_version2:"8.0.0.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.0.0.5", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
