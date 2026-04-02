# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0960.1");
  script_cve_id("CVE-2026-28295", "CVE-2026-28296");
  script_tag(name:"creation_date", value:"2026-03-25 04:41:01 +0000 (Wed, 25 Mar 2026)");
  script_version("2026-03-25T05:58:02+0000");
  script_tag(name:"last_modification", value:"2026-03-25 05:58:02 +0000 (Wed, 25 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-26 16:24:09 +0000 (Thu, 26 Feb 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0960-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0960-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260960-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258954");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024806.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gvfs' package(s) announced via the SUSE-SU-2026:0960-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gvfs fixes the following issues:

- CVE-2026-28295: information disclosure when processing untrusted PASV responses from FTP servers (bsc#1258953).
- CVE-2026-28296: arbitrary FTP command injection due to unsanitized CRLF sequences in user supplied file paths
 (bsc#1258954).");

  script_tag(name:"affected", value:"'gvfs' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"gvfs", rpm:"gvfs~1.52.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-32bit", rpm:"gvfs-32bit~1.52.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-afc", rpm:"gvfs-backend-afc~1.52.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-goa", rpm:"gvfs-backend-goa~1.52.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-samba", rpm:"gvfs-backend-samba~1.52.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backends", rpm:"gvfs-backends~1.52.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-devel", rpm:"gvfs-devel~1.52.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-fuse", rpm:"gvfs-fuse~1.52.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-lang", rpm:"gvfs-lang~1.52.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
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
