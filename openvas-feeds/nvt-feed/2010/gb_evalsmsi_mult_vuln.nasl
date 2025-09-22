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

CPE = "cpe:/a:myshell:evalsmsi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800166");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0614", "CVE-2010-0615", "CVE-2010-0616", "CVE-2010-0617");
  script_name("EvalSMSI < 2.2.00 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_evalsmsi_http_detect.nasl");
  script_mandatory_keys("evalsmsi/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38478");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38116");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56154");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56157");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56152");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1002-exploits/corelan-10-008-evalmsi.txt");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-008-evalmsi-2-1-03-multiple-vulnerabilities/");

  script_tag(name:"summary", value:"EvalSMSI is prone to multiple vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view, edit
  and delete the backend database via SQL Injection or inject arbitrary web script or HTML via a
  cross-site scripting (XSS) attack.");

  script_tag(name:"affected", value:"EvalSMSI prior to version 2.2.00.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Input passed to the 'query' parameter in ajax.php (when 'question' action is set), 'return'
  parameter in ajax.php and while writing comments to assess.php page (when 'continue_assess' action
  is set) is not properly sanitised before being used in SQL queries.

  - The passwords are stored in plaintext in the database, which allows attackers with database
  access to gain privileges.");

  script_tag(name:"solution", value:"Update to version 2.2.00 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"2.0.00")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.0.00", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
