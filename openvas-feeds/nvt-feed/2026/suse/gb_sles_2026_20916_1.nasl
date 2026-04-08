# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20916.1");
  script_cve_id("CVE-2025-53906", "CVE-2026-26269", "CVE-2026-28417");
  script_tag(name:"creation_date", value:"2026-04-03 04:47:54 +0000 (Fri, 03 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-03 17:50:29 +0000 (Tue, 03 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20916-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20916-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620916-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259051");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-April/025100.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the SUSE-SU-2026:20916-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

- Update Vim to version 9.2.0110 that includes security fixes for:
* CVE-2026-28417: crafted URL parsed by netrw plugin can lead to execute arbitrary shell commands (bsc#1259051).
* CVE-2026-26269: stack buffer overflow in Vim's NetBeans integration when processing the specialKeys command (bsc#1258229).
* CVE-2025-53906: path traversal in Vim's zip.vim plugin (bsc#1246602).

- Other changes:
* Add wayland-client to BuildRequires and enable Wayland support.
* Add Wayland include path to CFLAGS to fix clipboard compilation.
* Package new Swedish (sv) man pages and clean up duplicate encodings (sv.ISO8859-1 and sv.UTF-8).");

  script_tag(name:"affected", value:"'vim' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.2.0110~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.2.0110~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.2.0110~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.2.0110~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~9.2.0110~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xxd", rpm:"xxd~9.2.0110~160000.1.1", rls:"SLES16.0.0"))) {
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
