# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20988.1");
  script_cve_id("CVE-2026-28295", "CVE-2026-28296");
  script_tag(name:"creation_date", value:"2026-04-13 05:04:44 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-13T06:24:05+0000");
  script_tag(name:"last_modification", value:"2026-04-13 06:24:05 +0000 (Mon, 13 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-26 16:24:09 +0000 (Thu, 26 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20988-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20988-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620988-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258954");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045343.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-online-accounts, gvfs' package(s) announced via the SUSE-SU-2026:20988-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnome-online-accounts, gvfs fixes the following issues:

Changes for gvfs:

Update gvfs to 1.59.90:

- CVE-2026-28295: information disclosure when processing untrusted PASV responses from FTP servers (bsc#1258953).
- CVE-2026-28296: arbitrary FTP command injection due to unsanitized CRLF sequences in user supplied file paths
 (bsc#1258954).

Changelog:

Update to version 1.59.90:

 + client: Fix use-after-free when creating async proxy failed
 + udisks2: Emit changed signals from update_all()
 + daemon: Fix race on subscribers list when on thread
 + ftp: Validate fe_size when parsing symlink target
 + ftp: Check localtime() return value before use
 + gphoto2: Use g_try_realloc() instead of g_realloc()
 + cdda: Reject path traversal in mount URI host
 + client: Fail when URI has invalid UTF-8 chars
 + udisks2: Fix memory corruption with duplicate mount paths
 + build: Update GOA dependency to > 3.57.0
 + Some other fixes
 + ftp: Use control connection address for PASV data.
 + ftp: Reject paths containing CR/LF characters

Update to version 1.59.1:

 + mtp: replace Android extension checks with capability checks
 + dav: Add X-OC-Mtime header on push to preserve last modified
 time
 + udisks2: Use hash tables in the volume monitor to improve
 performance
 + onedrive: Check for identity instead of presentation identity
 + build: Disable google option and mark as deprecated

Update to version 1.58.2:

 + ftp: Use control connection address for PASV data
 + ftp: Reject paths containing CR/LF characters

Update to version 1.58.1:

 + cdda: Fix duration of last track for some media
 + build: Fix build when google option is disabled
 + Fix various memory leaks
 + Updated translations.

Update to version 1.58.0:

 + mtp: Allow cancelling ongoing folder enumerations
 + wsdd: Use socket-activated service if available
 + onedrive: Set emblem for remote data
 + fix: Add file rename support in MTP backend move operation
 + mtp: Fix -Wmaybe-uninitialized warning in pad_file
 + fuse: use fuse_(un)set_feature_flag for libfuse 3.17+
 + smbbrowse: Purge server cache for next auth try
 + metatree: Open files with O_CLOEXEC
 + cdda: Fix incorrect track duration for 99-track CDs
 + metadata: Fix journal file permissions inconsistency
 + dav: recognize 308 Permanent Redirect

Changes for gnome-online-accounts:

Update to version 3.58.0:

 + SMTP server without password cannot be configured
 + Remove unneeded SMTP password escaping
 + build: Disable google provider Files feature
 + MS365: Fix mail address and name
 + Google: Set mail name to presentation identity
 + Updated translations.

Update to version 3.57.1:

 + Default Microsoft 365 client is unverified
 + Microsoft 365: Make use of email for id
 + goadaemon: Allow manage system notifications
 + goamsgraphprovider: bump credentials generation
 + goaprovider: Allow to disable, instead of enable, selected
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'gnome-online-accounts, gvfs' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"gvfs", rpm:"gvfs~1.59.90~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backends", rpm:"gvfs-backends~1.59.90~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-fuse", rpm:"gvfs-fuse~1.59.90~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-lang", rpm:"gvfs-lang~1.59.90~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgoa-1_0-0", rpm:"libgoa-1_0-0~3.58.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgoa-backend-1_0-2", rpm:"libgoa-backend-1_0-2~3.58.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Goa-1_0", rpm:"typelib-1_0-Goa-1_0~3.58.0~160000.1.1", rls:"SLES16.0.0"))) {
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
