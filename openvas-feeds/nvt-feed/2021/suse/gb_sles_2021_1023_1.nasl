# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1023.1");
  script_cve_id("CVE-2020-28368", "CVE-2021-20257", "CVE-2021-28687", "CVE-2021-3308");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 17:06:43 +0000 (Tue, 22 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1023-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1023-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211023-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183072");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-April/008585.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2021:1023-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

- CVE-2021-3308: VUL-0: xen: IRQ vector leak on x86 (bsc#1181254, XSA-360)
- CVE-2021-28687: VUL-0: xen: HVM soft-reset crashes toolstack (bsc#1183072, XSA-368)
- CVE-2021-20257: VUL-0: xen: infinite loop issue in the e1000 NIC emulator (bsc#1182846)
- CVE-2020-28368: VUL-0: xen: Intel RAPL sidechannel attack aka PLATYPUS attack aka (bsc#1178591, XSA-351)
- L3: conring size for XEN HV's with huge memory to small. Inital Xen logs cut (bsc#1177204)
- Kdump of HVM fails, soft-reset not handled by libxl (bsc#1179148)
- OpenQA job causes libvirtd to dump core when running kdump inside domain (bsc#1181989)
- Allow restart of xenwatchdogd, enable tuning of keep-alive interval and timeout
 options via XENWATCHDOGD_ARGS= (bsc#1178736)
- The receiving side did detect holes in a to-be-allocated superpage, but allocated a superpage anyway.
 This resulted to over-allocation (bsc#1177112)
- The receiving side may punch holes incorrectly into optimistically allocated superpages.
 Also reduce overhead in bitmap handling (bsc#1177112)
- Upstream bug fixes (bsc#1027519)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.12.4_09~3.39.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.12.4_09~3.39.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.12.4_09~3.39.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.12.4_09~3.39.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.12.4_09~3.39.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.12.4_09~3.39.3", rls:"SLES12.0SP5"))) {
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
