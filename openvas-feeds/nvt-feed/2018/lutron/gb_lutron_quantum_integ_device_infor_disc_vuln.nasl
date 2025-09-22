# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lutron:device";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812953");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-7276", "CVE-2018-8880");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-18 11:08:00 +0000 (Sun, 18 Mar 2018)");
  script_tag(name:"creation_date", value:"2018-02-27 17:23:35 +0530 (Tue, 27 Feb 2018)");

  script_name("Lutron Quantum BACnet Integration Devices Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"Lutron Quantum BACnet Integration device is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks
  whether it is possible to read sensitive information or not.");

  script_tag(name:"insight", value:"The flaw exists due to broken access control mechanism in the device.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain potentially sensitive information via a '/DbXmlInfo.xml' request.");

  script_tag(name:"affected", value:"Lutron Quantum BACnet Integration 2.0 devices with firmware 3.2.243.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://misteralfa-hack.blogspot.in/2018/02/bacnet-entrando-en-materia.html");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_lutron_devices_detect.nasl");
  script_mandatory_keys("lutron/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!lutPort = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:lutPort, nofork: TRUE))
  exit(0);

url = '/DbXmlInfo.xml';

if(http_vuln_check(port:lutPort, url:url, pattern:"<Latitude>[ 0-9.-]+</Latitude>",
                   extra_check:make_list("<Copyright>Copyright.* Lutron Electronics",
                   "<Longitude>[ 0-9.-]+</Longitude>"))){
  report = http_report_vuln_url(port:lutPort, url:url);
  security_message(port:lutPort, data: report);
  exit(0);
}

exit(99);
