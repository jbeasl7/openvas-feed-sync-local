# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106270");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-20 09:58:46 +0700 (Tue, 20 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Yokogawa STARDOM Detection");

  script_tag(name:"summary", value:"Detection of Yokogawa STRARDOM

  The script sends a FTP connection request and attempts to detect the presence of Yokogawa STARDOM and to
  extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/yokogawa/stardom/detected");

  script_xref(name:"URL", value:"http://www.yokogawa.com/solutions/products-platforms/control-system/process-control-plc-rtu/");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = ftp_get_port(default: 21);
banner = ftp_get_banner(port: port);

if (banner && "FCX STARDOM" >< banner) {
  version = "unknown";

  mo = eregmatch(pattern: "STARDOM\(([A-Z0-9-]+)\)", string: banner);
  if (isnull(mo[1]))
    exit(0);

  model = mo[1];
  set_kb_item(name: "yokogawa_stardom/model", value: model);
  set_kb_item(name: "yokogawa_stardom/detected", value: TRUE);

  ver = eregmatch(pattern: "JRS:(R[0-9.]+)", string: banner);
  if (!isnull(ver[1])) {
    version = ver[1];
    set_kb_item(name: "yokogawa_stardom/version", value: version);
  }

  cpe = build_cpe(value: tolower(version), exp: "^(r[0-9.]+)", base: "cpe:/a:yokogawa:stardom_fcn-fcj:");
  if (!cpe)
    cpe = 'cpe:/a:yokogawa:stardom_fcn-fcj';

  register_product(cpe: cpe, location: port + '/tcp', port: port, service: "ftp");

  log_message(data: build_detection_report(app: "Yokogawa STARDOM " + model, version: version,
                                           install: port + "tcp", cpe: cpe, concluded: banner),
              port: port);
}

exit(0);
