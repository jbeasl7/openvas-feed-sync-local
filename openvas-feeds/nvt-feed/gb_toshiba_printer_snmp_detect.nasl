# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142905");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-09-18 02:50:20 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Toshiba Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Toshiba printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# TOSHIBA e-STUDIO3555C
# TOSHIBA e-STUDIO7506AC
# TOSHIBA TEC B-SA4T
# TOSHIBA TEC B-SX5T
# TOSHIBA TEC B-EX4T
if (sysdesc =~ "^TOSHIBA (e-STUDIO|TEC)") {
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "toshiba/printer/detected", value: TRUE);
  set_kb_item(name: "toshiba/printer/snmp/detected", value: TRUE);
  set_kb_item(name: "toshiba/printer/snmp/port", value: port);

  if (sysdesc =~ "^TOSHIBA TEC") {
    # nb:
    # - Information gathered from https://www.toshibatec.nl/upload/docs/b-ex4t2-spec09-en-0015-snmp-specification-15-edition-2016-11.pdf
    # - The sysdesc is not used for the model extraction as it might include the shorter "B-EX4T"
    #   while the model was actually "B-EX4T1-T"

    # B-FV4T-G
    # B-EX4T2-G
    mod_oid = "1.3.6.1.4.1.1129.1.2.1.1.1.2.1.0";
    mod = chomp(snmp_get(port: port, oid: mod_oid));
    if (!isnull(mod) && mod != "") {
      model = mod;
      set_kb_item(name: "toshiba/printer/snmp/" + port + "/concludedMod", value: mod);
      set_kb_item(name: "toshiba/printer/snmp/" + port + "/concludedModOID", value: mod_oid);
    }

    # V1.6H
    # C2.3
    # C2.0f
    fw_oid = "1.3.6.1.4.1.1129.1.2.1.1.1.2.2.0";
    vers = chomp(snmp_get(port: port, oid: fw_oid));
    if (!isnull(vers)) {
      version = vers;
      set_kb_item(name: "toshiba/printer/snmp/" + port + "/concludedFwOID", value: fw_oid);
    }
  } else {
    set_kb_item(name: "toshiba/printer/snmp/" + port + "/concluded", value: sysdesc);
    # TOSHIBA e-STUDIO339CS version CXTGV.221.068 kernel 5.4.90-yocto-standard All-N-1
    mod = eregmatch(pattern: "TOSHIBA ([^ ]+)( version ([.A-Z0-9]+))?", string: sysdesc);
    if (!isnull(mod[1]))
      model = mod[1];

    if (!isnull(mod[3]))
      version = mod[3];
    # nb: Seen on e.g.:
    # TOSHIBA e-STUDIO3505AC
    # TOSHIBA e-STUDIO2515AC
    if (version == "unknown") {
      vers_oid = "1.3.6.1.4.1.1129.2.3.50.1.2.4.1.62.1.1";
      vers = chomp(snmp_get(port: port, oid: vers_oid));

      # T373HD0W1304
      # TC01HD0W1600
      if (!isnull(vers) && vers != "") {
        version = vers;
        set_kb_item(name: "toshiba/printer/snmp/" + port + "/concludedFwOID", value: vers_oid);
      }
    }
  }

  set_kb_item(name: "toshiba/printer/snmp/" + port + "/model", value: model);
  set_kb_item(name: "toshiba/printer/snmp/" + port + "/fw_version", value: version);
}

exit(0);
