# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140295");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-14 12:10:48 +0700 (Mon, 14 Aug 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-12568", "CVE-2017-16249");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Debut Embedded Server DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("debut/banner");

  script_tag(name:"summary", value:"Debut embedded httpd server is prone to multiple denial of service
vulnerabilities.");

  script_tag(name:"insight", value:"- The Debut embedded httpd server is prone to a denial of service
vulnerability which allows a remote attacker to hang the printer by sending a large amount of HTTP packets.
(CVE-2017-12568)

  - The Debut embedded http server contains a remotely exploitable denial of service where a single malformed HTTP
POST request can cause the server to hang until eventually replying with an HTTP 500 error. While the server is
hung, print jobs over the network are blocked and the web interface is inaccessible. An attacker can continuously
send this malformed request to keep the device inaccessible to legitimate traffic. (CVE-2017-16249)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Debut embedded httpd 1.20 and prior (Brother/HP printer http admin)");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://gist.github.com/tipilu/53f142466507b2ef4c8ceb08d22d1278");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43119/");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default: 443);

banner = http_get_remote_headers(port: port);

vers = eregmatch(pattern: "debut/([0-9.]+)", string: banner);

if (!isnull(vers[1])) {
  if (version_is_less_equal(version: vers[1], test_version: "1.20")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "None");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
