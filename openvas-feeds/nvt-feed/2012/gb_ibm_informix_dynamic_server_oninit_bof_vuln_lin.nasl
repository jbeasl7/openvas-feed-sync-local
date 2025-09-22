# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:informix_dynamic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802291");
  script_version("2025-07-08T05:41:10+0000");
  script_tag(name:"last_modification", value:"2025-07-08 05:41:10 +0000 (Tue, 08 Jul 2025)");
  script_tag(name:"creation_date", value:"2012-01-12 17:17:17 +0530 (Thu, 12 Jan 2012)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2010-4053");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("IBM Informix Dynamic Server Buffer Overflow Vulnerability (Oct 2010) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_ibm_informix_dynamic_server_ssh_login_detect.nasl");
  script_mandatory_keys("ibm/informix/dynamic_server/ssh-login/detected");

  script_tag(name:"summary", value:"IBM Informix Dynamic Server is prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error within the logging function
  in oninit and can be exploited to cause a stack-based buffer overflow by sending a specially
  crafted request to TCP ports 9088 or 1526.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code with SYSTEM-level privileges.");

  script_tag(name:"affected", value:"IBM Informix Dynamic Server version 11.10.x prior to
  11.10.xC2W2 and 11.50.x prior to 11.50.xC1.");

  script_tag(name:"solution", value:"Update to version 11.50.xC1, 11.10.xC2W2 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41913");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44192");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62619");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-216");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^11\.[15]0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
