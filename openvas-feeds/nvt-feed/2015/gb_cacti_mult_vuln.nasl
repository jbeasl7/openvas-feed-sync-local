# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805664");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2015-4454", "CVE-2015-4342", "CVE-2015-2665", "CVE-2015-2967");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-07-20 10:16:48 +0530 (Mon, 20 Jul 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Cacti Multiple Vulnerabilities (Jun 2015)");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The 'get_hash_graph_template' function in lib/functions.php script in Cacti.

  - An insufficient sanitization of user-supplied data in HTTP request sent to graphs.

  - Unspecified vectors involving a cdef id

  - An insufficient sanitization of user-supplied data in settings.php in Cacti.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary SQL
commands, inject arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"affected", value:"Cacti version before 0.8.8d.");

  script_tag(name:"solution", value:"Upgrade to version 0.8.8d or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75108");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75669");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-15-017");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cacti_http_detect.nasl");
  script_mandatory_keys("cacti/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_less(version:version, test_version:"0.8.8d")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.8.8d");
  security_message(data:report, port:port);
  exit(0);
}

exit(0);
