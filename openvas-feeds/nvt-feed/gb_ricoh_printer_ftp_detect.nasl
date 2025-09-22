# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142809");
  script_version("2024-06-17T08:31:37+0000");
  script_tag(name:"last_modification", value:"2024-06-17 08:31:37 +0000 (Mon, 17 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-08-28 04:15:03 +0000 (Wed, 28 Aug 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RICOH Printer Detection (FTP)");

  script_tag(name:"summary", value:"FTP based detection of RICOH printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ricoh/printer/detected");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default: 21);
banner = ftp_get_banner(port: port);

# 220 RICOH MP 3053 FTP server (12.76.1) ready.
# 220 RICOH SP C250DN (d9e0d4) FTP server ready
# 220 RICOH Aficio MP C3000 FTP server (5.20.1) ready.
# 220 RICOH Pro C5210S FTP server (16.56.1) ready.
# 220 SAVIN MP C6004ex FTP server (15.62) ready.
# 220 NRG IM C3000 FTP server (19.05) ready.
# 220 LANIER MP C2004ex FTP server (15.77.1) ready.
# n.b. This is the Network Interface Board (NIB) version and not the firmware version
# n.b. Added complexity to the check since there are FTP Servers like '220 NRG FTP Server' that are not in fact printers
if (banner && banner =~ "^220 (RICOH|LANIER|SAVIN|Gestetner|NRG) (Aficio |Pro)?([A-Z]+)? [^ ]+ (\([^)]+\) )?FTP server") {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "ricoh/printer/detected", value: TRUE);
  set_kb_item(name: "ricoh/printer/ftp/detected", value: TRUE);
  set_kb_item(name: "ricoh/printer/ftp/port", value: port);
  set_kb_item(name: "ricoh/printer/ftp/" + port + "/concluded", value: banner);

  mod = eregmatch(pattern: "(RICOH|LANIER|SAVIN|Gestetner|NRG) ((Aficio |Pro)?([A-Z]+)? [^ ]+)", string: banner);
  if (!isnull(mod[2]))
    model = mod[2];

  if (!isnull(mod[1]))
    brand = mod[1];

  set_kb_item(name: "ricoh/printer/ftp/" + port + "/model", value: model);
  set_kb_item(name: "ricoh/printer/ftp/" + port + "/brand", value: brand);
  set_kb_item(name: "ricoh/printer/ftp/" + port + "/fw_version", value: version);
}

exit(0);
