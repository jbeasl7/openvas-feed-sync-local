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

CPE = "cpe:/a:redhat:jboss_enterprise_application_platform";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810320");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2015-5220", "CVE-2015-5188", "CVE-2015-5178");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-01-04 14:39:58 +0530 (Wed, 04 Jan 2017)");
  script_name("Red Hat JBoss Enterprise Application Platform (EAP) < 6.4.4 Multiple Vulnerabilities");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_red_hat_jboss_eap_http_detect.nasl");
  script_mandatory_keys("redhat/jboss/eap/detected");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1250552");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77345");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77346");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68444");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1252885");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1255597");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2015-1908.html");

  script_tag(name:"summary", value:"Red Hat JBoss Enterprise Application Platform (EAP) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The EAP console does not set the X-Frame-Options HTTP header.

  - The web Console does not properly validate a file upload using a multipart/form-data submission.

  - A Java OutOfMemoryError in the HTTP management interface while sending requests containing large
  headers to Web Console.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  clickjacking attack, to cause a denial of service, and hijack the authentication of administrators
  for requests that make arbitrary changes to an instance and to read arbitrary files.");

  script_tag(name:"affected", value:"Red Hat JBoss EAP versions before 6.4.4.");

  script_tag(name:"solution", value:"Update to version 6.4.4 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"6.4.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.4.4");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
