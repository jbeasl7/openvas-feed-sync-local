# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:asustor:adm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141533");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-09-28 10:15:18 +0700 (Fri, 28 Sep 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ASUSTOR ADM <= 3.0.5.RDU1 Authentication Bypass Vulnerability - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_asustor_adm_http_detect.nasl");
  script_mandatory_keys("asustor/adm/http/detected");
  script_require_ports("Services/www", 8000);

  script_tag(name:"summary", value:"ASUSTOR ADM is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability lies in the web interface of ASUSTOR NAS, in
  the file located in /initial/index.cgi, which responsible for initializing the device with your
  ASUSTOR ID. By abusing /initial/index.cgi?act=register, it is possible to log in with the
  administrator privileges without any kind of authentication.");

  script_tag(name:"affected", value:"ASUSTOR ADM version 3.0.5.RDU1 and prior.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3747");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/initial/index.cgi?act=register";

if (http_vuln_check(port: port, url: url, pattern: "SID = '", check_header: TRUE,
                    extra_check: "STATUS = 'register';")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
