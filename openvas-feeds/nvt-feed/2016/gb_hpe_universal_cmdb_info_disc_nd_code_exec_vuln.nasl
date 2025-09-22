# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:universal_cmbd_foundation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808251");
  script_version("2022-03-29T08:25:19+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-29 08:25:19 +0000 (Tue, 29 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-10 14:38:00 +0000 (Fri, 10 Jun 2016)");
  script_tag(name:"creation_date", value:"2016-07-14 16:30:56 +0530 (Thu, 14 Jul 2016)");

  script_cve_id("CVE-2016-4367", "CVE-2016-4368");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP/HPE/Micro Focus Universal CMDB Multiple Vulnerabilities (HPSBGN03622, HPSBGN03623)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_microfocus_universal_cmdb_http_detect.nasl");
  script_mandatory_keys("hp_microfocus/ucmdb/detected");

  script_tag(name:"summary", value:"HP/HPE/Micro Focus Universal CMDB CMDB is prone to remote
  information disclosure and code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified errors in the
  Universal Discovery component and Apache Commons Collections (ACC) library.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information via unspecified vectors and also to execute arbitrary commands.");

  script_tag(name:"affected", value:"HP/HPE/Micro Focus Universal CMDB versions 10.0, 10.01, 10.10,
  10.11, 10.20 and 10.21.");

  script_tag(name:"solution", value:"Apply the available patch.");

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-c05164813");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-c05164408");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1036050");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137370");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

affected = make_list("10.0", "10.01", "10.10", "10.11", "10.20", "10.21");

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
