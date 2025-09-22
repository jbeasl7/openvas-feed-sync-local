# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122454");
  script_cve_id("CVE-2009-2692", "CVE-2009-2698");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:39 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 15:22:00 +0000 (Thu, 28 Dec 2023)");

  script_name("Oracle: Security Advisory (ELSA-2009-1222)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1222");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1222.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-128.7.1.0.1.el5, oracleasm-2.6.18-128.7.1.0.1.el5' package(s) announced via the ELSA-2009-1222 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-128.7.1.0.1.el5]
- [NET] Add entropy support to e1000 and bnx2 (John Sobecki,Guru Anbalagane) [orabug 6045759]
- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]
- [nfs] convert ENETUNREACH to ENOTCONN (Guru Anbalagane) [orabug 7689332]
- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]
- [MM] balloon code needs to adjust totalhigh_pages (Chuck Anderson) [orabug 8300888]
- [NET] Add entropy support to igb ( John Sobecki) [orabug 7607479]
- [XEN] use hypercall to fixmap pte updates (Mukesh Rathor) [orabug 8433329]
- [XEN] Extend physical mask to 40bit for machine above 64G [orabug 8312526]

[2.6.18-128.7.1.el5]
- [net] prevent null pointer dereference in udp_sendmsg (Vitaly Mayatskikh) [518047 518043] {CVE-2009-2698}

[2.6.18-128.6.1.el5]
- [net] make sock_sendpage use kernel_sendpage (Jiri Pirko ) [517445 516955] {CVE-2009-2692}

[2.6.18-128.5.1.el5]
- [dlm] free socket in error exit path (David Teigland ) [515432 508829]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-128.7.1.0.1.el5, oracleasm-2.6.18-128.7.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.7.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.7.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.7.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.7.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.7.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.7.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.7.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.7.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.7.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.7.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.7.1.0.1.el5", rpm:"ocfs2-2.6.18-128.7.1.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.7.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-128.7.1.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.7.1.0.1.el5debug", rpm:"ocfs2-2.6.18-128.7.1.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.7.1.0.1.el5xen", rpm:"ocfs2-2.6.18-128.7.1.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.7.1.0.1.el5", rpm:"oracleasm-2.6.18-128.7.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.7.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-128.7.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.7.1.0.1.el5debug", rpm:"oracleasm-2.6.18-128.7.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.7.1.0.1.el5xen", rpm:"oracleasm-2.6.18-128.7.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
