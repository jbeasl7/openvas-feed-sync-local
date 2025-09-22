# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805579");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-06-02 11:37:07 +0530 (Tue, 02 Jun 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("IBM Domino Cross-Site Scripting Vulnerability (Jun 2015)");

  script_tag(name:"summary", value:"IBM Domino is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient authentication
  and insufficient brute force measures.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"IBM Domino 8.5.x through 8.5.4 and 9.x through 9.0.1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://securityvulns.ru/docs29277.html");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/May/128");
  script_xref(name:"URL", value:"http://www.zdnet.com/article/xss-flaw-exposed-in-ibm-domino-enterprise-platform");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"8.5", test_version2:"8.5.4")||
   version_in_range(version:version, test_version:"9.0", test_version2:"9.0.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None");
  security_message(data:report, port:0);
  exit(0);
}

exit(0);
