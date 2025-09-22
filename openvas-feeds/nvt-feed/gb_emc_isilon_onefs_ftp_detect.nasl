# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106553");
  script_version("2024-06-07T15:38:39+0000");
  script_tag(name:"last_modification", value:"2024-06-07 15:38:39 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-01-30 15:26:27 +0700 (Mon, 30 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell EMC PowerScale OneFS (Isilion OneFS) Detection (FTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/emc/isilon_onefs/detected");

  script_tag(name:"summary", value:"FTP based detection of Dell EMC PowerScale OneFS (formerly
  Isilion OneFS).");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default: 21);
banner = ftp_get_banner(port: port);

if (!banner || banner !~ "(Isilon|PowerScale) OneFS")
  exit(0);

version = "unknown";

set_kb_item(name: "dell/emc_isilon/onefs/detected", value: TRUE);
set_kb_item(name: "dell/emc_isilon/onefs/ftp/port", value: port);
set_kb_item(name: "dell/emc_isilon/onefs/ftp/" + port + "/concluded", value: banner);

vers = eregmatch(pattern: "(Isilon|PowerScale) OneFS v?([0-9.]+)", string: banner);
if (!isnull(vers[2]))
  version = vers[2];

set_kb_item(name: "dell/emc_isilon/onefs/ftp/" + port + "/version", value: version);

exit(0);
