# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140057");
  script_cve_id("CVE-2016-7476");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - TMM vulnerability CVE-2016-7476");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K87416818");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The Traffic Management Microkernel (TMM) may suffer from a memory leak while handling certain types of TCP traffic. (CVE-2016-7476)");

  script_tag(name:"impact", value:"Remote attackers may cause a denial of service (DoS) via a crafted TCP packet.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-06 15:11:00 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2016-11-14 14:11:08 +0100 (Mon, 14 Nov 2016)");
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

check_f5["LTM"] = make_array("affected",   "11.4.0-11.6.0;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;11.2.1;10.2.1-10.2.4;");

check_f5["AAM"] = make_array("affected",   "11.4.0-11.6.0;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;");

check_f5["AFM"] = make_array("affected",   "11.4.0-11.6.0;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;");

check_f5["APM"] = make_array("affected",   "11.4.0-11.6.0;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;11.2.1;10.2.1-10.2.4;");

check_f5["ASM"] = make_array("affected",   "11.4.0-11.6.0;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;11.2.1;10.2.1-10.2.4;");

check_f5["LC"]  = make_array("affected",   "11.4.0-11.6.0;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;11.2.1;10.2.1-10.2.4;");

check_f5["PEM"] = make_array("affected",   "11.4.0-11.6.0;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;");

check_f5["PSM"] = make_array("affected",   "11.4.0-11.4.1;",
                             "unaffected", "11.4.1_HF10;11.2.1;10.2.1-10.2.4;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
