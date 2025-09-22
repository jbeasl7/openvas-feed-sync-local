# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808180");
  script_version("2024-05-29T05:05:18+0000");
  script_cve_id("CVE-2016-4545");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-09 11:35:00 +0000 (Thu, 09 Jun 2016)");
  script_tag(name:"creation_date", value:"2016-07-04 10:59:05 +0530 (Mon, 04 Jul 2016)");
  script_tag(name:"qod_type", value:"package");
  script_name("F5 BIG-IP - SSL vulnerability CVE-2016-4545");

  script_tag(name:"summary", value:"F5 BIG-IP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On virtual servers with Secure Sockets Layer (SSL) profiles
  enabled, an SSL alert sent during the handshake may produce unnecessary logging and resource
  consumption on a BIG-IP, possibly causing the Traffic Management Microkernel (TMM) to restart and
  produce a core file.");

  script_tag(name:"impact", value:"When a Secure Sockets Layer (SSL) alert is sent during the
  handshake, the TMM may restart and produce a core file while logging SSL 'codec alert' messages to
  the /var/log/ltm file.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K48042976");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_f5_big_ip_ssh_login_detect.nasl");
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");
  exit(0);
}

include("f5.inc");
include("host_details.inc");
include("list_array_func.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, service: "ssh-login"))
  exit(0);

check_f5["LTM"] = make_array("affected",   "11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;10.2.1-10.2.4;");

check_f5["AAM"] = make_array("affected",   "11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.4.0-11.5.3;");

check_f5["AFM"] = make_array("affected",   "11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.3.0-11.5.3;");

check_f5["AVR"] = make_array("affected",   "11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;");

check_f5["APM"] = make_array("affected",   "11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;10.2.1-10.2.4;");

check_f5["ASM"] = make_array("affected",   "11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;10.2.1-10.2.4;");

check_f5["GTM"] = make_array("affected",   "11.5.4;",
                             "unaffected", "11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;10.2.1-10.2.4;");

check_f5["LC"]  = make_array("affected",   "11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.0.0-11.5.3;10.2.1-10.2.4;");

check_f5["PEM"] = make_array("affected",   "11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.0-11.6.1;11.5.4_HF1;11.3.0-11.5.3;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
