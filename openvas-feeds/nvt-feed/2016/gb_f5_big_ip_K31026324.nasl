# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105517");
  script_cve_id("CVE-2015-2925", "CVE-2015-5307", "CVE-2015-8104");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - Linux kernel vulnerabilities CVE-2015-2925, CVE-2015-5307, and CVE-2015-8104");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K31026324");

  script_tag(name:"impact", value:"A local user may be able to bypass a container protection mechanism by renaming a directory, or cause a denial-of-service (DoS) to the system by triggering certain exceptions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2015-2925
The prepend_path function in fs/dcache.c in the Linux kernel before 4.2.4 does not properly handle rename actions inside a bind mount, which allows local users to bypass an intended container protection mechanism by renaming a directory, related to a 'double-chroot attack'.

CVE-2015-5307
The KVM subsystem in the Linux kernel through 4.2.6, and Xen 4.3.x through 4.6.x, allows guest OS users to cause a denial of service (host OS panic or hang) by triggering many #AC (aka Alignment Check) exceptions, related to svm.c and vmx.c.

CVE-2015-8104
The KVM subsystem in the Linux kernel through 4.2.6, and Xen 4.3.x through 4.6.x, allows guest OS users to cause a denial of service (host OS panic or hang) by triggering many #DB (aka Debug) exceptions, related to svm.c.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"creation_date", value:"2016-01-19 12:04:32 +0100 (Tue, 19 Jan 2016)");
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

check_f5["LTM"] = make_array("affected",   "12.0.0;11.1.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.0.0;10.1.0-10.2.4;");

check_f5["AAM"] = make_array("affected",   "12.0.0;11.4.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;");

check_f5["AFM"] = make_array("affected",   "12.0.0;11.3.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;");

check_f5["AVR"] = make_array("affected",   "12.0.0;11.1.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.0.0;");

check_f5["APM"] = make_array("affected",   "12.0.0;11.1.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.0.0;10.1.0-10.2.4;");

check_f5["ASM"] = make_array("affected",   "12.0.0;11.1.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.0.0;10.1.0-10.2.4;");

check_f5["GTM"] = make_array("affected",   "11.1.0-11.6.0;",
                             "unaffected", "11.0.0;10.1.0-10.2.4;");

check_f5["LC"]  = make_array("affected",   "12.0.0;11.1.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.0.0;10.1.0-10.2.4;");

check_f5["PEM"] = make_array("affected",   "12.0.0;11.3.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;");

check_f5["PSM"] = make_array("affected",   "11.1.0-11.4.1;",
                             "unaffected", "11.0.0;10.1.0-10.2.4;");

check_f5["WAM"] = make_array("affected",   "11.1.0-11.3.0;",
                             "unaffected", "11.0.0;10.1.0-10.2.4;");

check_f5["WOM"] = make_array("affected",   "11.1.0-11.3.0;",
                             "unaffected", "11.0.0;10.1.0-10.2.4;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
