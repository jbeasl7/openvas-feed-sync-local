# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3938.1");
  script_cve_id("CVE-2020-15257");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:46 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 00:55:25 +0000 (Tue, 08 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3938-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3938-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203938-1/");
  script_xref(name:"URL", value:"https://github.com/docker/docker-ce/releases/tag/v19.03.14");
  script_xref(name:"URL", value:"https://github.com/moby/libnetwork/pull/2548");
  script_xref(name:"URL", value:"https://github.com/moby/libnetwork/pull/2548");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, docker, docker-runc, golang-github-docker-libnetwork' package(s) announced via the SUSE-SU-2020:3938-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, docker-runc,
golang-github-docker-libnetwork fixes the following issues:

Security issues fixed:

CVE-2020-15257: Fixed a privilege escalation in containerd (bsc#1178969).

Non-security issues fixed:

Update to containerd v1.3.9, which is needed for Docker v19.03.14-ce and
 fixes CVE-2020-15257. bsc#1180243

Update to containerd v1.3.7, which is required for Docker 19.03.13-ce.
 bsc#1176708

Update to Docker 19.03.14-ce. See upstream changelog in the packaged
 /usr/share/doc/packages/docker/CHANGELOG.md. CVE-2020-15257 bsc#1180243
 [link moved to references]

Enable fish-completion

Add a patch which makes Docker compatible with firewalld with nftables
 backend. Backport of [link moved to references]
 (bsc#1178801, SLE-16460)

Update to Docker 19.03.13-ce. See upstream changelog in the packaged
 /usr/share/doc/packages/docker/CHANGELOG.md. bsc#1176708

Fixes for %_libexecdir changing to /usr/libexec (bsc#1174075)

Emergency fix: %requires_eq does not work with provide symbols,
 only effective package names. Convert back to regular Requires.

Update to Docker 19.03.12-ce. See upstream changelog in the packaged
 /usr/share/doc/packages/docker/CHANGELOG.md.

Use Go 1.13 instead of Go 1.14 because Go 1.14 can cause all sorts of
 spurrious errors due to Go returning -EINTR from I/O syscalls much more
 often (due to Go 1.14's pre-emptive goroutine support).

Add BuildRequires for all -git dependencies so that we catch missing
 dependencies much more quickly.

Update to libnetwork 55e924b8a842, which is required for Docker
 19.03.14-ce. bsc#1180243

Add patch which makes libnetwork compatible with firewalld with nftables
 backend. Backport of [link moved to references]
 (bsc#1178801, SLE-16460)");

  script_tag(name:"affected", value:"'containerd, docker, docker-runc, golang-github-docker-libnetwork' package(s) on SUSE Linux Enterprise Module for Containers 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.3.9~16.32.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~19.03.14_ce~98.57.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~19.03.14_ce~98.57.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2908_55e924b8a842~34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2908_55e924b8a842~34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc10+gitr3981_dc9208a3303f~1.49.1", rls:"SLES12.0"))) {
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
