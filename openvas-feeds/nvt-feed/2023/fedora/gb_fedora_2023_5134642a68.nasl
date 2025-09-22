# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884791");
  script_cve_id("CVE-2023-40184");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:20 +0000 (Sat, 16 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-05 14:02:17 +0000 (Tue, 05 Sep 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-5134642a68)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-5134642a68");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-5134642a68");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236307");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236308");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xrdp' package(s) announced via the FEDORA-2023-5134642a68 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Release notes for xrdp v0.9.23 (2023/08/31)

General announcements

 - Running xrdp and xrdp-sesman on separate hosts is still supported by this release, but is now deprecated. This is not secure. A future v1.0 release will replace the TCP socket used between these processes with a Unix Domain Socket, and then cross-host running will not be possible.

Security fixes

 - CVE-2023-40184: Improper handling of session establishment errors allows bypassing OS-level session restrictions (Reported by @gafusss)

Bug fixes

 - Environment variables set by PAM modules are no longer restricted to around 250 characters (#2712)
 - X11 clipboard clients now no longer hang when requesting a clipboard format which isn't available (#2767)

New features

No new features in this release.
Internal changes

 - Introduce release tarball generation script (#2703)
 - cppcheck version used for CI bumped to 2.11 (#2738)

Known issues

 - On-the-fly resolution change requires the Microsoft Store version of Remote Desktop client but sometimes crashes on connect (#1869)
 - xrdp's login dialog is not relocated at the center of the new resolution after on-the-fly resolution change happens (#1867)");

  script_tag(name:"affected", value:"'xrdp' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"xrdp", rpm:"xrdp~0.9.23~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-debuginfo", rpm:"xrdp-debuginfo~0.9.23~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-debugsource", rpm:"xrdp-debugsource~0.9.23~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-devel", rpm:"xrdp-devel~0.9.23~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-selinux", rpm:"xrdp-selinux~0.9.23~1.fc39", rls:"FC39"))) {
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
