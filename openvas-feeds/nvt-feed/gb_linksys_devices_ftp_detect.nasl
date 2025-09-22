# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144535");
  script_version("2024-03-26T05:06:00+0000");
  script_tag(name:"last_modification", value:"2024-03-26 05:06:00 +0000 (Tue, 26 Mar 2024)");
  script_tag(name:"creation_date", value:"2020-09-08 06:33:40 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Linksys Device Detection (FTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/linksys/detected");

  script_tag(name:"summary", value:"FTP based detection of Linksys devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default: 21);

if (!banner = ftp_get_banner(port: port))
  exit(0);

# 220 Welcome to Linksys
if ("Welcome to Linksys" >< banner) {
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "linksys/detected", value: TRUE);
  set_kb_item(name: "linksys/ftp/detected", value: TRUE);
  set_kb_item(name: "linksys/ftp/port", value: port);
  set_kb_item(name: "linksys/ftp/" + port + "/concluded", value: banner);
  set_kb_item(name: "linksys/ftp/" + port + "/model", value: model);
  set_kb_item(name: "linksys/ftp/" + port + "/version", value: version);
}

exit(0);
