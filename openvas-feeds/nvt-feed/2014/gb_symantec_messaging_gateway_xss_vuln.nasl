# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804440");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-05-02 11:16:59 +0530 (Fri, 02 May 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-1648");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symantec Messaging Gateway 10.x < 10.5.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_messaging_gateway_consolidation.nasl");
  script_mandatory_keys("symantec/smg/detected");

  script_tag(name:"summary", value:"Symantec Messaging Gateway is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to input passed via the 'displayTab' GET
  parameter to /brightmail/setting/compliance/DlpConnectFlow$view.flo is not properly sanitised
  before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway version 10.x prior to 10.5.2.");

  script_tag(name:"solution", value:"Update to version 10.5.2 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66966");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126264/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Apr/256");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
