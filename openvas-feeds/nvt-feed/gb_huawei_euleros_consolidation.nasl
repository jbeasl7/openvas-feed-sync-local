# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143355");
  script_version("2021-07-13T13:08:53+0000");
  script_tag(name:"last_modification", value:"2021-07-13 13:08:53 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-01-15 02:15:18 +0000 (Wed, 15 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei EulerOS Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Huawei EulerOS detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_huawei_euleros_ssh_login_detect.nasl", "gb_huawei_euleros_snmp_detect.nasl");
  script_mandatory_keys("huawei/euleros/detected");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros");

  exit(0);
}

if (!get_kb_item("huawei/euleros/detected"))
  exit(0);

include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_sp      = "unknown";

foreach source (make_list("ssh-login", "snmp")) {
  version_list = get_kb_list("huawei/euleros/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      set_kb_item(name: "huawei/euleros/version", value: version);
      break;
    }
  }

  sp_list = get_kb_list("huawei/euleros/" + source + "/*/sp");
  foreach service_pack (sp_list) {
    if (service_pack && detected_sp == "unknown") {
      detected_sp = service_pack;
      set_kb_item(name: "huawei/euleros/sp", value: service_pack);
      break;
    }
  }
}

os_cpe = "cpe:/o:huawei:euleros";
os_key = "EULEROS";
app_name = "Huawei EulerOS";

if (detected_version != "unknown") {

  if (get_kb_item("ssh/login/euleros/is_uvp_arm")) {

    os_cpe += "_virtualization_for_arm_64:" + detected_version;
    os_key += "VIRTARM64-" + detected_version;
    app_name += " Virtualization (UVP) for ARM 64";

  } else if (get_kb_item("ssh/login/euleros/is_uvp")) {

    os_cpe += "_virtualization:" + detected_version;
    os_key += "VIRT-" + detected_version;
    app_name += " Virtualization (UVP)";

  } else {

    os_cpe += ":" + detected_version;
    os_key += "-" + detected_version;

    if (detected_sp != "unknown") {
      os_cpe += ":sp" + detected_sp;
      os_key += "SP" + detected_sp;
      service_pack = "SP" + detected_sp;
    } else {
      os_cpe += ":sp0";
      os_key += "SP0";
    }

    if (os_key_add = get_kb_item("huawei/euleros/ssh-login/oskey_addition")) {
      os_cpe += ":" + tolower(os_key_add);
      os_key += "-" + os_key_add;
    }
  }
}

os_register_and_report(os: app_name, cpe: os_cpe, desc: "Huawei EulerOS Detection Consolidation",
                       runs_key: "unixoide");

location = "/";
extra = ""; # nb: To make openvas-nasl-lint happy...

if (ssh_ports = get_kb_list("huawei/euleros/ssh-login/port")) {
  set_kb_item(name: "ssh/login/release", value: os_key);

  foreach port (ssh_ports) {
    if (extra)
      extra += '\n';
    extra += "SSH login on port " + port + "/tcp";

    concluded = get_kb_item("huawei/euleros/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '\n  Concluded from version/product identification result: ' + concluded;

    concluded_location = get_kb_item("huawei/euleros/ssh-login/" + port + "/concluded_location");
    if (concluded_location)
      extra += '\n  Concluded from version/product identification location: ' + concluded_location;

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
  }
}

if (snmp_ports = get_kb_list("huawei/euleros/snmp/port")) {
  foreach port (snmp_ports) {
    if (extra)
      extra += '\n';
    extra += "SNMP on port " + port + "/udp";

    concluded = get_kb_item("huawei/euleros/snmp/" + port + "/concluded");
    concludedOID = get_kb_item("huawei/euleros/snmp/" + port + "/concludedOID");
    if (concluded && concludedOID)
      extra += '\n  Concluded from ' + concluded + ' via OID: ' + concludedOID;

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report = build_detection_report(app: app_name, version: detected_version, patch: service_pack,
                                install: location, cpe: os_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);