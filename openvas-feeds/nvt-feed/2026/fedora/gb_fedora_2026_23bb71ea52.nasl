# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.239898711019752");
  script_cve_id("CVE-2026-32766", "CVE-2026-33056");
  script_tag(name:"creation_date", value:"2026-03-30 04:59:52 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-24 16:17:11 +0000 (Tue, 24 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-23bb71ea52)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-23bb71ea52");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-23bb71ea52");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448054");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449243");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449274");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449338");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449547");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449549");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449645");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449681");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449683");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449684");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449694");
  script_xref(name:"URL", value:"https://github.com/DoctorJohn/fastar/releases/tag/v0.9.0");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/blob/0.10.12/CHANGELOG.md");
  script_xref(name:"URL", value:"https://github.com/nix-rust/nix/blob/v0.31.2/CHANGELOG.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'maturin, python-fastar, python-uv-build, rust-astral-tokio-tar, rust-nix, rust-tar, uv' package(s) announced via the FEDORA-2026-23bb71ea52 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update `rust-astral-tokio-tar` to 0.6.0, fixing CVE-2026-32766. Update `rust-tar` to 0.4.45, fixing CVE-2026-33056. Update `rust-nix` to [0.31.2]([link moved to references]). Update `uv` and `python-uv-build` to [0.10.2]([link moved to references]), rebuilding them with the latest `rust-astral-tokio-tar` and `rust-tar`. Update `python-fastar` to [0.9.0]([link moved to references]), rebuilding it with the lastest `rust-tar`. Rebuild `maturin` with the latest `rust-tar`.");

  script_tag(name:"affected", value:"'maturin, python-fastar, python-uv-build, rust-astral-tokio-tar, rust-nix, rust-tar, uv' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"maturin", rpm:"maturin~1.9.6~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin-debuginfo", rpm:"maturin-debuginfo~1.9.6~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin-debugsource", rpm:"maturin-debugsource~1.9.6~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-fastar", rpm:"python-fastar~0.8.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-fastar-debugsource", rpm:"python-fastar-debugsource~0.8.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build", rpm:"python-uv-build~0.10.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build-debugsource", rpm:"python-uv-build-debugsource~0.10.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastar", rpm:"python3-fastar~0.8.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastar-debuginfo", rpm:"python3-fastar-debuginfo~0.8.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv", rpm:"python3-uv~0.10.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build", rpm:"python3-uv-build~0.10.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build-debuginfo", rpm:"python3-uv-build-debuginfo~0.10.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar+default-devel", rpm:"rust-astral-tokio-tar+default-devel~0.6.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar+xattr-devel", rpm:"rust-astral-tokio-tar+xattr-devel~0.6.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar", rpm:"rust-astral-tokio-tar~0.6.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar-devel", rpm:"rust-astral-tokio-tar-devel~0.6.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+acct-devel", rpm:"rust-nix+acct-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+aio-devel", rpm:"rust-nix+aio-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+default-devel", rpm:"rust-nix+default-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+dir-devel", rpm:"rust-nix+dir-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+env-devel", rpm:"rust-nix+env-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+event-devel", rpm:"rust-nix+event-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+fanotify-devel", rpm:"rust-nix+fanotify-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+feature-devel", rpm:"rust-nix+feature-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+fs-devel", rpm:"rust-nix+fs-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+hostname-devel", rpm:"rust-nix+hostname-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+inotify-devel", rpm:"rust-nix+inotify-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+ioctl-devel", rpm:"rust-nix+ioctl-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+kmod-devel", rpm:"rust-nix+kmod-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+memoffset-devel", rpm:"rust-nix+memoffset-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+mman-devel", rpm:"rust-nix+mman-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+mount-devel", rpm:"rust-nix+mount-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+mqueue-devel", rpm:"rust-nix+mqueue-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+net-devel", rpm:"rust-nix+net-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+personality-devel", rpm:"rust-nix+personality-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+pin-utils-devel", rpm:"rust-nix+pin-utils-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+poll-devel", rpm:"rust-nix+poll-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+process-devel", rpm:"rust-nix+process-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+pthread-devel", rpm:"rust-nix+pthread-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+ptrace-devel", rpm:"rust-nix+ptrace-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+quota-devel", rpm:"rust-nix+quota-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+reboot-devel", rpm:"rust-nix+reboot-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+resource-devel", rpm:"rust-nix+resource-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+sched-devel", rpm:"rust-nix+sched-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+signal-devel", rpm:"rust-nix+signal-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+socket-devel", rpm:"rust-nix+socket-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+syslog-devel", rpm:"rust-nix+syslog-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+term-devel", rpm:"rust-nix+term-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+time-devel", rpm:"rust-nix+time-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+ucontext-devel", rpm:"rust-nix+ucontext-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+uio-devel", rpm:"rust-nix+uio-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+user-devel", rpm:"rust-nix+user-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix+zerocopy-devel", rpm:"rust-nix+zerocopy-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix", rpm:"rust-nix~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nix-devel", rpm:"rust-nix-devel~0.31.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tar+default-devel", rpm:"rust-tar+default-devel~0.4.45~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tar+xattr-devel", rpm:"rust-tar+xattr-devel~0.4.45~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tar", rpm:"rust-tar~0.4.45~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tar-devel", rpm:"rust-tar-devel~0.4.45~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv", rpm:"uv~0.10.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debuginfo", rpm:"uv-debuginfo~0.10.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debugsource", rpm:"uv-debugsource~0.10.12~1.fc42", rls:"FC42"))) {
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
