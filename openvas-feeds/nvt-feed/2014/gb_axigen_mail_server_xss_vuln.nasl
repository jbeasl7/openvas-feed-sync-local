# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:axigen:axigen_mail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804669");
  script_version("2024-02-23T05:07:12+0000");
  script_cve_id("CVE-2012-2592");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-23 05:07:12 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-07-07 14:34:53 +0530 (Mon, 07 Jul 2014)");

  script_name("AXIGEN Mail Server Email Message Cross-site Scripting Vulnerability");

  script_tag(name:"summary", value:"Axigen Mail Server is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to application which does not validate input passed via an
email message before returning it to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary script code
in a user's browser within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Axigen Mail Server version 8.0.1");

  script_tag(name:"solution", value:"Upgrade to Axigen Mail Server version 8.1.0 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54899");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/77515");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_axigen_webmail_http_detect.nasl");
  script_mandatory_keys("axigen/detected");
  script_xref(name:"URL", value:"http://www.axigen.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!axigenVer = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: axigenVer, test_version:"8.0.1")) {
  report = report_fixed_ver(installed_version: axigenVer, fixed_version: "8.1.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
