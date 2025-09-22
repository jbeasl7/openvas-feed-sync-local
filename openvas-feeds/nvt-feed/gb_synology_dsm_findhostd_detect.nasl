# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153104");
  script_version("2024-09-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-09-19 05:05:57 +0000 (Thu, 19 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-13 08:22:10 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology NAS / DiskStation Manager Detection (findhostd)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_synology_findhostd_udp_detect.nasl");
  script_mandatory_keys("synology/findhostd/detected");
  script_require_udp_ports("Services/udp/findhostd", 9999);

  script_tag(name:"summary", value:"findhostd based detection of Synology NAS devices, DiskStation
  Manager (DSM) OS and application.");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("port_service_func.inc");

if (!port = service_get_port(nodefault: TRUE, ipproto: "udp", proto: "findhostd"))
  exit(0);

if (!resp = get_kb_item("synology/findhostd/" + port + "/response"))
  exit(0);

if (hexstr(resp) !~ "^1234567853594E4F")
  exit(0);

version = "unknown";
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

for (i = 8; i < strlen(resp); i++) {
  type = ord(resp[i]);
  len = ord(resp[i + 1]);
  i += 2;
  value = substr(resp, i, i + len - 1);
  i += len - 1;

  if (type == 25) {
    register_host_detail(name: "MAC", value: value, desc: "Synology NAS / DiskStation Manager Detection (findhostd)");
    replace_kb_item(name: "Host/mac_address", value: value);
  } else if (type == 120) {
    model = value;
    concluded += '\n    Model:            ' + model;
  } else if (type == 119) {
    vers = value;
    concluded += '\n    Product Version:  ' + vers;
  } else if (type == 73) {
    build = getword(blob: value);
    concluded += '\n    Build:            ' + build;
  } else if (type == 144) {
    fix = getword(blob: value);
    concluded += '\n    Small Fix Number: ' + fix;
  }
}

if (model) {
  set_kb_item(name: "synology/dsm/detected", value: TRUE);
  set_kb_item(name: "synology/dsm/findhostd/detected", value: TRUE);
  set_kb_item(name: "synology/dsm/findhostd/port", value: port);

  if (vers) {
    version = vers;
    if (build) {
      version += "-" + build;
      if (fix) {
        version += "-" + fix;
      }
    }
  }

  set_kb_item(name: "synology/dsm/findhostd/" + port + "/model", value: model);
  set_kb_item(name: "synology/dsm/findhostd/" + port + "/version", value: version);
  set_kb_item(name: "synology/dsm/findhostd/" + port + "/concluded", value: concluded);
}

exit(0);
