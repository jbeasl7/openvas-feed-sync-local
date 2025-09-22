# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140300");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-15 16:05:13 +0700 (Tue, 15 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Biscom Secure File Transfer Detection");

  script_tag(name:"summary", value:"Detection of Biscom Secure File Transfer.

The script sends a connection request to the server and attempts to detect Biscom Secure File Transfer and to
extract its firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.biscom.com/secure-file-transfer/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 443);

foreach dir (make_list_unique("/fm", "/bds", "/aps", "/filestore", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/Login.do");

  if ((">Biscom SFT<" >< res || ">Biscom Secure File Transfer<" >< res) && "bds.uploader.js" >< res) {
    version = "unknown";

    vers = eregmatch(pattern: "\.css\?v=([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "biscom_sft/version", value: version);
    }

    set_kb_item(name: "biscom_sft/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:biscom:secure_file_transfer:");
    if (!cpe)
      cpe = 'cpe:/a:biscom:secure_file_transfer';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Biscom Secure File Transfer", version: version,
                                             install: install, cpe: cpe, concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
