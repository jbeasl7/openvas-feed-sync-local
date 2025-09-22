# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:magnoware:datatrack_system";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902062");
  script_version("2022-03-02T09:44:00+0000");
  script_tag(name:"last_modification", value:"2022-03-02 09:44:00 +0000 (Wed, 02 Mar 2022)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2010-2043", "CVE-2010-2078", "CVE-2010-2079");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("DataTrack System <= 3.5 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_datatrack_system_http_detect.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("datatrack_system/http/detected");

  script_tag(name:"summary", value:"DataTrack System is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An input passed via the 'Work_Order_Summary' parameter to 'Home.aspx' in the 'DataTrack Web
  Client' is not properly sanitised before being displayed to the user.

  - An improper validation of user supplied input, which can be exploited to disclose the contents
  of the 'root' directory, read arbitrary files, via a trailing backslash in a 'URL'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML code in a user's browser session in the context of an affected site and to obtain
  sensitive information.");

  script_tag(name:"affected", value:"DataTrack System version 3.5 (3.5.8019.4) and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58732");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58735");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58734");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1005-exploits/datatrackserver35-xss.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/web.config%5C";

if (http_vuln_check(port: port, url: url, pattern: "<(configuration|system\.web>", icase: FALSE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

url = "/%u00A0/";

if (http_vuln_check(port: port, url: url, pattern: ">Directory Listing",
                    extra_check: "(Bin/|Web\.config)", icase: FALSE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
