# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902010");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-12-31 08:44:14 +0100 (Thu, 31 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3580", "CVE-2009-3581", "CVE-2009-3582",
                "CVE-2009-3583", "CVE-2009-3584", "CVE-2009-4402");
  script_name("SQL-Ledger Multiple Vulnerabilities");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_sql_ledger_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sql-ledger/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct cross-site request
  forgery attacks and by malicious users to conduct script insertion and SQL
  injection attacks, or bypass certain security restrictions.");

  script_tag(name:"affected", value:"SQL-Ledger version 2.8.24 and prior.");

  script_tag(name:"insight", value:"- The application allows users to perform certain actions via HTTP requests
  without performing any validity checks to verify the request. This can be
  exploited to perform actions with the privileges of a target user, who is
  tricked into visiting a malicious website.

  - Input passed via customer names, vendor names, the DCN description field
  in 'Accounts Receivables', and the description field in 'Accounts Payable',
  is not properly sanitised before being used. This can be exploited to
  insert arbitrary HTML and script code, which is executed in a user's browser
  session in context of an affected site when the malicious data is viewed.

  - Input passed via the 'id' parameter when searching for vendors is not
  properly sanitised before being used in SQL queries. This can be exploited
  to manipulate SQL queries by injecting arbitrary SQL code.

  - Input passed via the 'countrycode' field in 'Preferences' is not properly
  sanitised before used to include files. This can be exploited to include
  arbitrary '.pl' files from the local system via directory traversal attacks.");

  script_tag(name:"solution", value:"Upgrade to SQL-Ledger version 2.8.30 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"SQL-Ledger is prone to multiple vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37877");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37431");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54964");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-12/0415.html");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

ledgerPort = http_get_port(default:80);

ledgerVer = get_kb_item("www/"+ ledgerPort + "/SQL-Ledger");
if(!ledgerVer)
  exit(0);

ledgerVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ledgerVer);
if(ledgerVer[1] != NULL)
{
  if(version_is_less_equal(version:ledgerVer[1], test_version:"2.8.24")){
    report = report_fixed_ver(installed_version:ledgerVer[1], vulnerable_range:"Less than or equal to 2.8.24");
    security_message(port: ledgerPort, data: report);
  }
}
