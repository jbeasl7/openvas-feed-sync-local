# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144581");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2020-09-16 06:29:54 +0000 (Wed, 16 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HCL / IBM / Lotus Domino Detection (SMTP)");

  script_tag(name:"summary", value:"SMTP based detection of HCL Domino (formerly Lotus/IBM Domino).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl");
  script_mandatory_keys("smtp/hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("smtp_func.inc");

port = smtp_get_port(default: 25);

banner = smtp_get_banner(port: port);

if (banner && banner =~ "(HCL|IBM|Lotus) Domino") {
  set_kb_item(name: "hcl/domino/detected", value: TRUE);
  set_kb_item(name: "hcl/domino/smtp/port", value: port);
  set_kb_item(name: "hcl/domino/smtp/" + port + "/concluded", value: banner);

  version = "unknown";

  # mail.example.com ESMTP Service (IBM Domino Release 10.0.1FP4) ready at Wed, 16 Sep 2020 08:26:32 +0200
  # example.com  ESMTP Service (IBM Domino Release 9.0.1FP10 HF383) ready at Wed, 16 Sep 2020 11:40:58 +0530
  # example.com ESMTP Service (IBM Domino Release 9.0.1FP7HF92) ready at Wed, 16 Sep 2020 16:21:42 +1000
  # example.com ESMTP Service (Lotus Domino Release 8.5.1) ready at Wed, 16 Sep 2020 16:16:29 +1000
  # mail.example.com ESMTP Service (HCL Domino Release 11.0.1) ready at Wed, 16 Sep 2020 00:36:55 -0400
  vers = eregmatch(pattern: "Release ([^)]+)", string: banner);
  if (!isnull(vers[1])) {
    version = str_replace(string: vers[1], find: "FP", replace: ".");
    version = ereg_replace(string: version, pattern: "( )?HF", replace: ".HF");
  }

  set_kb_item(name: "hcl/domino/smtp/" + port + "/version", value: version);
}

exit(0);
