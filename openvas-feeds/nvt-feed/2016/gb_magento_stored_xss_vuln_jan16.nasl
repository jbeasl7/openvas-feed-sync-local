# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:magentocommerce:magento";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806672");
  script_version("2022-03-03T11:20:36+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-03-03 11:20:36 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-01-28 18:09:47 +0530 (Thu, 28 Jan 2016)");
  script_name("Magento Stored XSS Vulnerability (SUPEE-7405)");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_xref(name:"URL", value:"https://magento.com/security/patches/supee-7405");
  script_xref(name:"URL", value:"https://blog.sucuri.net/2016/01/security-advisory-stored-xss-in-magento.html");

  script_tag(name:"summary", value:"Magento is prone to a stored cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the
  app/design/adminhtml/default/default/template/sales/order/view/info.phtml script where email
  address given by user is not validated before using it in backend.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote attackers to take
  over affected site, create new administrator accounts, steal client information and do anything a
  legitimate administrator account can do.");

  script_tag(name:"affected", value:"Magento prior to version 1.9.2.3 (CE) and 1.14.2.3 (EE).");

  script_tag(name:"solution", value:"Update to version 1.9.2.3 (CE), 1.14.2.3 (EE) or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# nb: Don't exit if empty as we always want to fallback to the CE check below if no edition could be
# gathered in the detection VT.
edition = get_kb_item("magento/edition/" + port + "/" + location);

if (edition == "EE") {
  if (version_is_less(version: version, test_version: "1.14.2.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.14.2.3", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "1.9.2.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.9.2.3", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
