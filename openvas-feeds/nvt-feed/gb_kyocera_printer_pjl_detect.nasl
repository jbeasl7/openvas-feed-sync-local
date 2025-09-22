# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147516");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2022-01-26 07:20:05 +0000 (Wed, 26 Jan 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kyocera Printer Detection (PJL)");

  script_tag(name:"summary", value:"Printer Job Language (PJL) based detection of Kyocera printer
  devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_pcl_pjl_detect.nasl");
  script_require_ports("Services/hp-pjl", 9100);
  script_mandatory_keys("hp-pjl/banner/available");

  exit(0);
}

port = get_kb_item("hp-pjl/port");

banner = get_kb_item("hp-pjl/" + port + "/banner");
if (!banner || banner !~ "^(TASKalfa|ECOSYS|FS-4[12]00DN)")
  exit(0);

model = "unknown";
fw_version = "unknown";

set_kb_item(name: "kyocera/printer/detected", value: TRUE);
set_kb_item(name: "kyocera/printer/hp-pjl/detected", value: TRUE);
set_kb_item(name: "kyocera/printer/hp-pjl/port", value: port);
set_kb_item(name: "kyocera/printer/hp-pjl/" + port + "/concluded", value: banner);

# TASKalfa 3051ci
model = chomp(banner);

set_kb_item(name: "kyocera/printer/hp-pjl/" + port + "/model", value: model);
set_kb_item(name: "kyocera/printer/hp-pjl/" + port + "/fw_version", value: fw_version);

exit(0);
