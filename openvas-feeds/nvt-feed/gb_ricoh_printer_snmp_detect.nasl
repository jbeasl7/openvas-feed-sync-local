# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142806");
  script_version("2024-06-19T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-19 05:05:42 +0000 (Wed, 19 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-08-27 08:44:37 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RICOH Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of RICOH printer devices.");

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

# RICOH MP 3053 1.16 / RICOH Network Printer C model / RICOH Network Scanner C model / RICOH Network Facsimile C model
# RICOH Aficio MP 201 1.04 / RICOH Network Printer C model / RICOH Network Scanner C model / RICOH Network Facsimile C model
# RICOH SP C252DN V1.02 / RICOH Network Printer C model
# RICOH Pro C5100S
# RICOH Pro C5310S 1.03 / RICOH Network Printer C model / RICOH Network Scanner C model
# RICOH IM C3510 JPN 1.10.1 / RICOH Network Printer C model / RICOH Network Scanner C model / RICOH Network Facsimile C model
# RICOH Pro C7210S
# RICOH Pro 8310
# SAVIN 9040 1.18 / SAVIN Network Printer C model / SAVIN Network Scanner C model
# LANIER MP 6054 1.22 / LANIER Network Printer C model / LANIER Network Scanner C model
# NRG MP C2050 1.21 / NRG Network Printer C model / NRG Network Scanner C model

if (sysdesc =~ "^(RICOH|LANIER|SAVIN|NRG)" && (sysdesc =~ "(RICOH|LANIER|SAVIN|NRG) Network Printer" ||
    egrep(pattern: "^RICOH (Pro|SP)", string: sysdesc, icase: TRUE))) {
  model = "unknown";
  brand = "unknown";
  version = "unknown";

  set_kb_item(name: "ricoh/printer/detected", value: TRUE);
  set_kb_item(name: "ricoh/printer/snmp/detected", value: TRUE);
  set_kb_item(name: "ricoh/printer/snmp/port", value: port);
  set_kb_item(name: "ricoh/printer/snmp/" + port + "/concluded", value: sysdesc);

  vers = eregmatch(pattern: "(RICOH|LANIER|SAVIN|NRG) ((Aficio |Pro)?([A-Z]+)? ?[^, ]+)( JPN)?( V?([0-9.]+))?", string: sysdesc);
  if (!isnull(vers[1]))
    brand = vers[1];

  if (!isnull(vers[2]))
    model = vers[2];

  if (!isnull(vers[7]))
    version = vers[7];

  if (version == "unknown") {
    # RICOH SP 230SFNw, Firmware Ver.D  ,MID 8C5-KE5FID 2
    vers = eregmatch(pattern: "(RICOH|LANIER|SAVIN|NRG) (([A-Z]+)? ?[^,]+), Firmware Ver.([A-Z]{1,2})", string: sysdesc);

    if (!isnull(vers[1]))
      brand = vers[1];

    if (!isnull(vers[2]))
      model = vers[2];

    if (!isnull(vers[4]))
      version = vers[4];
  }

  # nb: Seen on e.g.:
  # RICOH Pro 8310
  # RICOH Pro C7210S
  if (version == "unknown") {
    vers_oid = "1.3.6.1.4.1.367.3.2.1.1.1.2.0";
    vers = chomp(snmp_get(port: port, oid: vers_oid));

    # 1.0_SP1
    if (!isnull(vers) && vers != "") {
      version = vers;
      set_kb_item(name: "ricoh/printer/snmp/" + port + "/concludedFwOID", value: vers_oid);
    }
  }

  set_kb_item(name: "ricoh/printer/snmp/" + port + "/model", value: model);
  set_kb_item(name: "ricoh/printer/snmp/" + port + "/brand", value: brand);
  set_kb_item(name: "ricoh/printer/snmp/" + port + "/fw_version", value: version);
}

exit(0);
