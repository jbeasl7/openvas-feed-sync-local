# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:canon:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803718");
  script_version("2024-08-09T15:39:05+0000");
  script_tag(name:"last_modification", value:"2024-08-09 15:39:05 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"creation_date", value:"2013-06-19 12:00:59 +0530 (Wed, 19 Jun 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-4613", "CVE-2013-4614", "CVE-2013-4615");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Canon Printer Multiple Vulnerabilities (Jun 2013) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_canon_printer_consolidation.nasl");
  script_mandatory_keys("canon/printer/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple Canon printers are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"- Printers do not require a password for the administrative
  interfaces by default. Unauthorized users on the network may configure the printer.

  - Administrative interface on these printers allow a user to enter a WEP/WPA/WPA2 pre-shared key.
  Once a key is entered, when a user browses the configuration page again, they can view the
  current password in clear-text.

  - Administrative interface on the devices, Using specially crafted HTTP requests, it is possible
  to cause the device to no longer respond.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
  the denial of service and obtain the sensitive information.");

  script_tag(name:"affected", value:"Multiple Canon printers.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122073/");
  script_xref(name:"URL", value:"http://www.mattandreko.com/2013/06/canon-y-u-no-security.html");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/canon-printer-dos-secret-disclosure");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

url = "/English/pages_MacUS/wls_set_content.html";

if (http_vuln_check(port: port, url: url, pattern: ">Authentication Type:",
                    extra_check: make_list(">Passphrase:", ">Password"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
