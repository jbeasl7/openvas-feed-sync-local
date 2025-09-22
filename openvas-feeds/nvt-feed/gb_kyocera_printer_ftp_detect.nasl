# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147533");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2022-01-27 09:47:10 +0000 (Thu, 27 Jan 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kyocera Printer Detection (FTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/kyocera/printer/detected");

  script_tag(name:"summary", value:"FTP based detection of Kyocera printer devices.");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default: 21);
banner = ftp_get_banner(port: port);

# 220 ECOSYS M4125idn FTP server
# 220 ECOSYS P2235dn FTP server
# 220 TASKalfa 4052ci FTP server
# 220 FS-4200DN FTP server
if (banner && "FTP server" >< banner && banner =~ "(TASKalfa|ECOSYS|FS-4[12]00DN) ") {
  model = "unknown";
  fw_version = "unknown";

  set_kb_item(name: "kyocera/printer/detected", value: TRUE);
  set_kb_item(name: "kyocera/printer/ftp/detected", value: TRUE);
  set_kb_item(name: "kyocera/printer/ftp/port", value: port);
  set_kb_item(name: "kyocera/printer/ftp/" + port + "/concluded", value: banner);

  mod = eregmatch(pattern: "(((TASKalfa|ECOSYS) [^ ]+)|FS-4[12]00DN)", string: banner);
  if (!isnull(mod[1]))
    model = mod[1];

  set_kb_item(name: "kyocera/printer/ftp/" + port + "/model", value: model);
  set_kb_item(name: "kyocera/printer/ftp/" + port + "/fw_version", value: fw_version);
}

exit(0);
