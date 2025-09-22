# SPDX-FileCopyrightText: 2005 Corsaire Limited.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19508");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("TFTP file detection (HP Ignite-UX)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Corsaire Limited.");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "tftpd_backdoor.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"solution", value:"If it is not required, disable or uninstall the TFTP server.
  Otherwise restrict access to trusted sources only.");

  script_tag(name:"summary", value:"The remote host has a TFTP server installed that is serving one or more
  sensitive HP Ignite-UX files.");

  script_tag(name:"impact", value:"These files potentially include sensitive information about the hardware and
  software configuration of the HPUX host, so should not be exposed to unnecessary scrutiny.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

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

file_list = make_list(
"/var/opt/ignite/config.local", "/var/opt/ignite/local/config", "/var/opt/ignite/local/host.info",
"/var/opt/ignite/local/hw.info", "/var/opt/ignite/local/install.log", "/var/opt/ignite/local/manifest/manifest",
"/var/opt/ignite/recovery/makrec.append", "/var/opt/ignite/server/ignite.defs", "/var/opt/ignite/server/preferences");

foreach file_name(file_list) {
  if(tftp_get(port:port, path:file_name)) {
    detected_files += file_name + '\n';
  }
}

if(detected_files) {
  report = 'The filenames detected are:\n\n' + detected_files;
  security_message(port:port, data:report, proto:"udp");
  exit(0);
}

exit(99);
