# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/o:technicolor:tc7200_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811656");
  script_version("2022-12-15T10:11:09+0000");
  script_cve_id("CVE-2014-1677");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-15 10:11:09 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:42:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-09-08 17:01:34 +0530 (Fri, 08 Sep 2017)");
  script_name("Technicolor TC7200 Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_technicolor_tc7200_snmp_detect.nasl");
  script_mandatory_keys("technicolor/tc7200/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/31894/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/538955/100/0/threaded");

  script_tag(name:"summary", value:"Technicolor TC7200 devices are prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The web interface does not use cookies at all and does not check
  the IP address of the client. If admin login is successful, every user from the LAN can access the
  management interface.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information.");

  script_tag(name:"affected", value:"Technicolor TC7200 with firmware version STD6.01.12.");

  script_tag(name:"solution", value:"Update the firmware version STD6.02 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(vers == "std6.01.12") {
  report = report_fixed_ver(installed_version: toupper(vers), fixed_version: "STD6.02");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
