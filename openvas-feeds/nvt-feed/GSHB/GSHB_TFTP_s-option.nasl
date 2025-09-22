# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96101");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-05 15:06:40 +0200 (Wed, 05 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check if an TFTP Server is running and was start with -s Option");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "tftpd_detect.nasl");

  script_tag(name:"summary", value:"Check if an TFTP Server is running and was start with -s Option.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("tftp.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp", ignore_unscanned:TRUE);

if(tftp_alive(port:port)) {
  get = tftp_get(port:port, path:"//etc//passwd");
  if(!get)
    tftp = "ok";
  else
    tftp = "fail";
} else {
  tftp = "none";
}

set_kb_item(name:"GSHB/TFTP/s-option", value:tftp);

exit(0);
