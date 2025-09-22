# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122689");
  script_cve_id("CVE-2007-0005", "CVE-2007-0006", "CVE-2007-0771", "CVE-2007-0958", "CVE-2007-1000", "CVE-2007-1388", "CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1592", "CVE-2007-1861", "CVE-2007-2172", "CVE-2007-2242");
  script_tag(name:"creation_date", value:"2015-10-08 11:51:09 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2007-0347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0347");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0347.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-8.1.4.0.1.el5, oracleasm-2.6.18-8.1.4.0.1.el5' package(s) announced via the ELSA-2007-0347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-8.1.4.0.1.el5]
 -Fix bonding primary=ethX so it picks correct network (Bert Barbe) [IT
 101532] [ORA 5136660]
 -Add entropy module option to e1000 (John Sobecki) [ORA 6045759]
 -Add entropy module option to bnx2 (John Sobecki) [ORA 6045759]

 [2.6.18.8.1.4.el5]
 - [ipv6] Fix routing regression. (David S. Miller ) [238046]
 - [mm] Gdb does not accurately output the backtrace. (Dave Anderson )
 [235511]
 - [NMI] change watchdog timeout to 30 seconds (Larry Woodman ) [237655]
 - [dlm] fix mode munging (David Teigland ) [238731]
 - [net] kernel-headers: missing include of types.h (Neil Horman ) [238749]
 - [net] fib_semantics.c out of bounds check (Thomas Graf ) [238948]
 {CVE-2007-2172}
 - [net] disallow RH0 by default (Thomas Graf ) [238949] {CVE-2007-2242}
 - [net] Fix user OOPS'able bug in FIB netlink (David S. Miller )
 [238960] {CVE-2007-1861}
 - [net] IPv6 fragments bypass in nf_conntrack netfilter code (Thomas
 Graf ) [238947] {CVE-2007-1497}
 - [net] ipv6_fl_socklist is inadvertently shared (David S. Miller )
 [238944] {CVE-2007-1592}
 - [net] Various NULL pointer dereferences in netfilter code (Thomas Graf
 ) [238946] {CVE-2007-1496}

 [2.6.18-8.1.3.el5]
 - [s390] page_mkclean causes data corruption on s390 (Jan Glauber ) [236605]

 [2.6.18-8.1.2.el5]
 - [utrace] exploit and unkillable cpu fixes (Roland McGrath ) [228816]
 (CVE-2007-0771)
 - [net] IPV6 security holes in ipv6_sockglue.c - 2 (David S. Miller )
 [232257] {CVE-2007-1000}
 - [net] IPV6 security holes in ipv6_sockglue.c (David S. Miller )
 [232255] {CVE-2007-1388}
 - [audit] GFP_KERNEL allocations in non-blocking context fix (Alexander
 Viro ) [233157]

 [2.6.18-8.1.1.el5]
 - [cpufreq] Remove __initdata from tscsync (Prarit Bhargava ) [229887]
 - [security] Fix key serial number collision problem (David Howells )
 [229883] {CVE-2007-0006}
 - [fs] Don't core dump read-only binarys (Don Howard ) [229885]
 {CVE-2007-0958}
 - [xen] Enable booting on machines with > 64G (Chris Lalancette) [230117]
 - Fix potential buffer overflow in cardman 4040 cmx driver (Don Howard)
 [229884] {CVE-2007-0005}");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-8.1.4.0.1.el5, oracleasm-2.6.18-8.1.4.0.1.el5' package(s) on Oracle Linux 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~8.1.4.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~8.1.4.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~8.1.4.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~8.1.4.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~8.1.4.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~8.1.4.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~8.1.4.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~8.1.4.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-8.1.4.0.1.el5", rpm:"ocfs2-2.6.18-8.1.4.0.1.el5~1.2.6~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-8.1.4.0.1.el5PAE", rpm:"ocfs2-2.6.18-8.1.4.0.1.el5PAE~1.2.6~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-8.1.4.0.1.el5xen", rpm:"ocfs2-2.6.18-8.1.4.0.1.el5xen~1.2.6~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-8.1.4.0.1.el5", rpm:"oracleasm-2.6.18-8.1.4.0.1.el5~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-8.1.4.0.1.el5PAE", rpm:"oracleasm-2.6.18-8.1.4.0.1.el5PAE~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-8.1.4.0.1.el5xen", rpm:"oracleasm-2.6.18-8.1.4.0.1.el5xen~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
