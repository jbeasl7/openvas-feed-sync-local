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

CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140471");
  script_version("2021-09-10T14:01:42+0000");
  script_tag(name:"last_modification", value:"2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-11-02 09:34:01 +0700 (Thu, 02 Nov 2017)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-12274");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Aironet Access Point Platforms Extensible Authentication Protocol Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_wlc_consolidation.nasl");
  script_mandatory_keys("cisco/wlc/detected", "cisco/wlc/model");

  script_tag(name:"summary", value:"A vulnerability in Extensible Authentication Protocol (EAP) ingress frame
processing for the Cisco Aironet 1560, 2800, and 3800 Series Access Points could allow an unauthenticated, Layer
2 radio frequency (RF) adjacent attacker to cause the Access Point (AP) to reload, resulting in a denial of
service (DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient validation of the EAP frame. An
attacker could exploit this vulnerability by sending a malformed EAP frame to the targeted device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause the AP to reload,
resulting in a DoS condition while the AP is reloading. It may be necessary to manually power cycle the device in
order for it to recover.");

  script_tag(name:"solution", value:"See the referenced advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-aironet2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco/wlc/model");
if (!model || ((model !~ "^AIR-AP156[0-9]") && (model !~ "^AIR-AP(28|38)[0-9]{2}")))
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^8\.2\.") {
  if (version_is_less(version: version, test_version: "8.2.164.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.2.164.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^8\.3\.") {
  if (version_is_less(version: version, test_version: "8.3.132.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.3.132.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^8\.4\.") {
  if (version_is_less(version: version, test_version: "8.4.100.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.4.100.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^8\.5\.") {
  if (version_is_less(version: version, test_version: "8.5.105.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.5.105.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
