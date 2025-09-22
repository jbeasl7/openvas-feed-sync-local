# SPDX-FileCopyrightText: 2005 Corsaire Limited.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19510");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2004-0952");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_name("TFTP directory permissions (HP Ignite-UX)");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2005 Corsaire Limited.");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "tftpd_backdoor.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://www.corsaire.com/advisories/c041123-002.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14571");

  script_tag(name:"solution", value:"Upgrade to a version of the Ignite-UX application that does not exhibit
   this behaviour. If it is not required, disable or uninstall the TFTP server. Otherwise restrict access to trusted sources only.");

  script_tag(name:"summary", value:"The remote host has a vulnerable version of the HP Ignite-UX application
   installed that exposes a world-writeable directory to anonymous TFTP access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("tftp.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

if(!tftp_has_reliable_get(port:port))
  exit(0);

vtstrings = get_vt_strings();

file_name = "/var/opt/ignite/" + vtstrings["lowercase"] + "_tftp_test_" + rand();
if(tftp_put(port:port, path:file_name)) {
  report = 'It was possible to upload the following file:\n\n' + file_name;
  security_message(port:port, data:report, proto:"udp");
  exit(0);
}

exit(99);
