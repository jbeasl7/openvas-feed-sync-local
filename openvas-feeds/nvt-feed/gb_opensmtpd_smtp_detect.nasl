# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153174");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-24 09:18:55 +0000 (Tue, 24 Sep 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenSMTPD Detection (SMTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/opensmtpd/detected");

  script_tag(name:"summary", value:"SMTP based detection of OpenSMTPD.");

  script_xref(name:"URL", value:"https://www.opensmtpd.org/");

  exit(0);
}

include("host_details.inc");
include("smtp_func.inc");
include("port_service_func.inc");

port = smtp_get_port(default: 25);

banner = smtp_get_banner(port: port);
if (!banner || "ESMTP OpenSMTPD" >!< banner)
  exit(0);

version = "unknown";
location = "/";
concluded = banner;

set_kb_item(name: "opensmtpd/detected", value: TRUE);
set_kb_item(name: "opensmtpd/smtp/detected", value: TRUE);

cpe = "cpe:/a:openbsd:opensmtpd";

register_product(cpe: cpe, location: location, port: port, service: "smtp");

log_message(data: build_detection_report(app: "OpenSMTPD", version: version, install: location, cpe: cpe,
                                         concluded: concluded),
            port: port);

exit(0);
