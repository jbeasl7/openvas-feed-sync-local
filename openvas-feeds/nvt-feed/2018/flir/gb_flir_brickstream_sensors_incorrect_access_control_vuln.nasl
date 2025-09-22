# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flir:brickstream_sensor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812370");
  script_version("2025-03-24T05:38:38+0000");
  script_cve_id("CVE-2018-3813");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-24 05:38:38 +0000 (Mon, 24 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-17 18:15:00 +0000 (Wed, 17 Jan 2018)");
  script_tag(name:"creation_date", value:"2018-01-02 17:29:37 +0530 (Tue, 02 Jan 2018)");
  script_name("Flir Brickstream Sensors Incorrect Access Control Vulnerability (Aug 2018) - Active Check");

  script_tag(name:"summary", value:"Flir Brickstream Sensor is prone to an incorrect access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends the crafted http GET request
  and checks whether it is able to access the administration or not.");

  script_tag(name:"insight", value:"The flaw exists due to incorrect access control
  measures taken by the sensor.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to access administration of the device.");

  script_tag(name:"affected", value:"Flir Brickstream 2300 devices are known to be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://misteralfa-hack.blogspot.in/2018/01/brickstream-recuento-y-seguimiento-de.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_flir_brickstream_sensors_detect.nasl");
  script_mandatory_keys("Flir/Brickstream/Installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/getConfigExportFile.cgi";

if (http_vuln_check(port:port, url:url, pattern:"AVI_USER_ID=",
                    extra_check:make_list("AVI_USER_PASSWORD=", "AVI_SERVER_ADDRESS=", "AVI_USER_ID="),
                    check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
