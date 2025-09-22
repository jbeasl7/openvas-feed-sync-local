# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802623");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-04-09 15:15:15 +0530 (Mon, 09 Apr 2012)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Distinct TFTP Server <= 3.01 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "tftpd_backdoor.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"summary", value:"Distinct TFTP Server is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted TFTP request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused due an input validation error within the
  TFTP service and can be exploited to download or manipulate files in arbitrary locations outside
  the TFTP root via specially crafted directory traversal sequences.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to obtain sensitive
  information and launch further attacks.");

  script_tag(name:"affected", value:"Distinct TFTP Server version 3.01 and prior.");

  script_tag(name:"solution", value:"Update to version 3.11 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52938");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18718");
  script_xref(name:"URL", value:"http://www.spentera.com/advisories/2012/SPN-01-2012.pdf");

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
  res = tftp_get(path: "../../../../../../../../../../../../../../" + files[file], port: port);
  if(!res)
    continue;

  if (egrep(pattern: file, string: res, icase: TRUE)){
    report = "The " + files[file] + ' file contains:\n' + res;
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(99);
