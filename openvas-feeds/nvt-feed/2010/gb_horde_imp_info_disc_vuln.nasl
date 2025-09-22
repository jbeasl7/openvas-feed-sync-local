# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800288");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2010-0463");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde IMP <= 4.3.6 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("horde_http_detect.nasl");
  script_mandatory_keys("horde/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Horde IMP is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when DNS prefetching of domain names contained
  in links within e-mail messages.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to determine the
  network location of the webmail user by logging DNS requests.");

  script_tag(name:"affected", value:"Horde IMP version 4.3.6 and prior.");

  script_tag(name:"solution", value:"Apply the appropriate patch from vendor.");

  script_xref(name:"URL", value:"http://bugs.horde.org/ticket/8836");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2010-0463");
  script_xref(name:"URL", value:"https://secure.grepular.com/DNS_Prefetch_Exposure_on_Thunderbird_and_Webmail");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

res = http_get_cache(port: port, item: dir + "/test.php");

if ("imp" >< res || "IMP" >< res) {
  vers = eregmatch(pattern: "IMP: H3 .([0-9.]+)" , string: res);
  if (!isnull(vers[1])) {
    if (version_is_less_equal(version: vers[1], test_version: "4.3.6")) {
      report = report_fixed_ver(installed_version: vers[1], fixed_version: "See advisory");
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(0);
