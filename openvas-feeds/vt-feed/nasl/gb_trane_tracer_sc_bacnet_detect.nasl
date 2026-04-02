# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106272");
  script_version("2026-03-25T05:58:02+0000");
  script_tag(name:"last_modification", value:"2026-03-25 05:58:02 +0000 (Wed, 25 Mar 2026)");
  script_tag(name:"creation_date", value:"2016-09-20 16:39:00 +0700 (Tue, 20 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trane Tracer SC / SC+ Devices Detection (BACnet)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_bacnet_detect.nasl");
  script_mandatory_keys("bacnet/vendor", "bacnet/model_name");

  script_tag(name:"summary", value:"BACnet based detection of Trane Tracer SC / SC+.");

  exit(0);
}

vendor = get_kb_item("bacnet/vendor");
if (!vendor || "Trane" >!< vendor)
  exit(0);

model = get_kb_item("bacnet/model_name");
if (!model || model !~ "Tracer SC")
  exit(0);

sw_version = "unknown";
port = 47808;

if (model =~ "^Tracer SC\+")
  base_kb = "trane/tracer/sc_plus";
else
  base_kb = "trane/tracer/sc";

set_kb_item(name: "trane/tracer/sc_or_sc_plus/detected", value: TRUE);
set_kb_item(name: base_kb + "/detected", value: TRUE);
set_kb_item(name: base_kb + "/bacnet/detected", value: TRUE);
set_kb_item(name: base_kb + "/bacnet/port", value: port);

version = get_kb_item("bacnet/application_sw");
ver = eregmatch(pattern: "v([0-9.]+)", string: version);
if (!isnull(ver[1])) {
  sw_version = ver[1];
  set_kb_item(name: base_kb + "/bacnet/" + port + "/concluded", value: version);
}

set_kb_item(name: base_kb + "/bacnet/" + port + "/version", value: sw_version);

exit(0);
