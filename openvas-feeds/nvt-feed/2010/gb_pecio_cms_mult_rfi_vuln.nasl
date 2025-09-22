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

CPE = "cpe:/a:pecio-cms:pecio_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801444");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-3204");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Pecio CMS <= 2.0.5 Multiple RFI Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pecio_cms_http_detect.nasl");
  script_mandatory_keys("pecio_cms/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61433");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42806");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14815/");
  script_xref(name:"URL", value:"http://eidelweiss-advisories.blogspot.com/2010/08/pecio-cms-v205-template-multiple-remote.html");

  script_tag(name:"summary", value:"Pecio CMS is prone to multiple remote file inclusion (RFI)
  vulnerabilities.");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'post.php', 'article.php',
  'blog.php' and 'home.php' files, which are not properly validating the input data supplied to the
  'template' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attacker to obtain
  sensitive information or to execute malicious PHP code in the context of the webserver process.");

  script_tag(name:"affected", value:"Pecio CMS version 2.0.5 is known to be affected. Other versions
  might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"2.0.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);