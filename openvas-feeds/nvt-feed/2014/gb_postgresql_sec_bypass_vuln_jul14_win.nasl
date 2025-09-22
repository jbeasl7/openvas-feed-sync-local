# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804710");
  script_version("2024-07-19T05:05:32+0000");
  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063",
                "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2014-07-07 14:54:12 +0530 (Mon, 07 Jul 2014)");
  script_name("PostgreSQL Multiple Security Bypass Vulnerability (Jul 2014) - Windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple security bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error when handling roles can be exploited to revoke access from other
  role members.

  - Multiple errors when handling calls to PL validator functions.

  - Some errors when handling name lookups.

  - Some boundary errors when handling wide datetime input/output.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to bypass certain security
  restrictions, cause a DoS (Denial of Service), and potentially compromise a vulnerable system.");

  script_tag(name:"affected", value:"PostgreSQL version before 8.4.20, 9.0.x before 9.0.16, 9.1.x before 9.1.12,
  9.2.x before 9.2.7, and 9.3.x before 9.3.3");

  script_tag(name:"solution", value:"Upgrade to version 9.3.3, 9.2.7, 9.1.12, 9.0.16 or 8.4.20, or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57054");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65719");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65723");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65724");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65725");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65731");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/91277");
  script_xref(name:"URL", value:"http://wiki.postgresql.org/wiki/20140220securityrelease");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(vers !~ "^(8\.4|9\.[0-3])\.")
  exit(99);

if(version_in_range(version:vers, test_version:"8.4", test_version2:"8.4.19") ||
   version_in_range(version:vers, test_version:"9.0", test_version2:"9.0.15") ||
   version_in_range(version:vers, test_version:"9.1", test_version2:"9.1.11") ||
   version_in_range(version:vers, test_version:"9.2", test_version2:"9.2.6") ||
   version_in_range(version:vers, test_version:"9.3", test_version2:"9.3.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
