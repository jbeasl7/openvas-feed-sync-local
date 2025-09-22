# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142502");
  script_version("2023-03-02T10:19:53+0000");
  script_tag(name:"last_modification", value:"2023-03-02 10:19:53 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"creation_date", value:"2019-06-11 09:04:55 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-11 01:49:00 +0000 (Thu, 11 Jul 2019)");

  script_cve_id("CVE-2017-8226", "CVE-2017-8227", "CVE-2017-8228", "CVE-2017-8229",
                "CVE-2017-8230", "CVE-2017-13719");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Amcrest Technologies IP Cameras Multiple Vulnerabilities (Jun 2019)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  # nb: No dependency to gb_amcrest_ip_camera_http_detect.nasl because different models / devices or
  # even branded devices might be affected as well...
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Amcrest Technologies IP Cameras are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if it is possible to access the configuration file
  without authentication on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-8226: Default credentials

  - CVE-2017-8227: No account lockout or timeout for brute force attempts performed using the ONVIF
  specification

  - CVE-2017-8228: Missing owner check

  - CVE-2017-8229: The file /current_config/Sha1Account1 is accessible without authentication which
  contains unencrypted credentials.

  - CVE-2017-8230: Privilege escalation using HTTP APIs

  - CVE-2017-13719: Memory corruption issue");

  script_tag(name:"impact", value:"An unauthenticated attacker may e.g. obtain sensitive information
  like admin credentials and use this for further attacks.");

  script_tag(name:"affected", value:"Amcrest IPM-721S devices with firmware version
  V2.420.AC00.16.R.20160909 and prior (CVE-2017-8226, CVE-2017-8227, CVE-2017-8228, CVE-2017-8229,
  CVE-2017-8230) or version V2.420.AC00.17.R.20170322 and prior (CVE-2017-13719) are known to be
  affected. Other devices, vendors or firmware versions might be affected as well.");

  script_tag(name:"solution", value:"According to 3rdparty sources Amcrest has provided firmware
  updates to fix these flaws. Please contact the vendor for more information.");

  script_xref(name:"URL", value:"https://github.com/ethanhunnt/IoT_vulnerabilities/blob/master/Amcrest_sec_issues.pdf");
  script_xref(name:"URL", value:"https://github.com/ethanhunnt/IoT_vulnerabilities");
  script_xref(name:"URL", value:"https://seclists.org/bugtraq/2019/Jun/8");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/153224/Amcrest-IPM-721S-Credential-Disclosure-Privilege-Escalation.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/");

if (!res || "version=@WebVersion@" >!< res)
  exit(0);

url = "/current_config/Sha1Account1";

if (http_vuln_check(port: port, url: url, pattern: '"Password" : "', check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
