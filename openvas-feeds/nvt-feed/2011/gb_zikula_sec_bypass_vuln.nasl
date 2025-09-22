# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zikula:zikula_application_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801744");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2010-4728");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Zikula < 1.3.1 Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
  script_mandatory_keys("zikula/detected");

  script_xref(name:"URL", value:"http://code.zikula.org/core/ticket/2009");

  script_tag(name:"insight", value:"The flaw exists due to errors in 'rand' and 'srand' PHP functions for random
  number generation.");

  script_tag(name:"solution", value:"Update to version 1.3.1 or later.");

  script_tag(name:"summary", value:"Zikula is prone to a security bypass vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to defeat protection
  mechanisms based on randomization by predicting a return value.");

  script_tag(name:"affected", value:"Zikula versions prior to 1.3.1.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"1.3.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.3.1", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
