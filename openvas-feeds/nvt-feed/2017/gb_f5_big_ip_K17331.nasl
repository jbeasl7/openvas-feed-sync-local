# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140179");
  script_cve_id("CVE-2015-5073", "CVE-2016-9244");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - PCRE library vulnerability CVE-2015-5073");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K17331");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Heap-based buffer overflow in the find_fixedlength function in pcre_compile.c in PCRE before 8.38 allows remote attackers to cause a denial of service (crash) or obtain sensitive information from heap memory and possibly bypass the ASLR protection mechanism via a crafted regular expression with an excess closing parenthesis.");

  script_tag(name:"impact", value:"A local, authenticated attacker may be able to provide malicious input in the configuration to exploit this vulnerability. There is no data plane exposure to this issue.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-18 01:29:00 +0000 (Fri, 18 May 2018)");
  script_tag(name:"creation_date", value:"2017-03-07 10:27:32 +0100 (Tue, 07 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

check_f5["LTM"] = make_array("affected",   "12.0.0-12.1.2;11.0.0-11.6.1;10.1.0-10.2.4;",
                             "unaffected", "13.0.0;");

check_f5["AAM"] = make_array("affected",   "12.0.0-12.1.2;11.4.0-11.6.1;",
                             "unaffected", "13.0.0;");

check_f5["AFM"] = make_array("affected",   "12.0.0-12.1.2;11.3.0-11.6.1;",
                             "unaffected", "13.0.0;");

check_f5["AVR"] = make_array("affected",   "12.0.0-12.1.2;11.0.0-11.6.1;",
                             "unaffected", "13.0.0;");

check_f5["APM"] = make_array("affected",   "12.0.0-12.1.2;11.0.0-11.6.1;10.1.0-10.2.4;",
                             "unaffected", "13.0.0;");

check_f5["ASM"] = make_array("affected",   "12.0.0-12.1.2;11.0.0-11.6.1;10.1.0-10.2.4;",
                             "unaffected", "13.0.0;");

check_f5["LC"]  = make_array("affected",   "12.0.0;11.0.0-11.6.1;10.1.0-10.2.4;",
                             "unaffected", "13.0.0;");

check_f5["PEM"] = make_array("affected",   "12.0.0-12.1.2;11.3.0-11.6.1;",
                             "unaffected", "13.0.0;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
