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

CPE = "cpe:/a:redhat:jboss_enterprise_application_platform";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810314");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2015-5304");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-12-16 19:22:06 +0530 (Fri, 16 Dec 2016)");
  script_name("Red Hat JBoss Enterprise Application Platform (EAP) < 6.4.5 DoS Vulnerability");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_red_hat_jboss_eap_http_detect.nasl");
  script_mandatory_keys("redhat/jboss/eap/detected");

  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2015-2541.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79788");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2015-5304");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2015-5304");

  script_tag(name:"summary", value:"Red Hat JBoss Enterprise Application Platform (EAP) is prone to
  a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because Red Hat JBoss EAP is not properly
  authorize access to shutdown the server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users
  with the monitor, deployer, or auditor role to cause a denial of service.");

  script_tag(name:"affected", value:"Red Hat JBoss EAP server versions before 6.4.5.");

  script_tag(name:"solution", value:"Update to version 6.4.5 or later.");

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

if(version_is_less(version:vers, test_version:"6.4.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.4.5");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
