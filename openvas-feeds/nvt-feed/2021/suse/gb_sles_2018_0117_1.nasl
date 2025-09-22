# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0117.1");
  script_cve_id("CVE-2017-16548", "CVE-2017-17433", "CVE-2017-17434");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-22 19:52:57 +0000 (Fri, 22 Dec 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0117-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180117-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071460");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003603.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsync' package(s) announced via the SUSE-SU-2018:0117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rsync fixes the following issues:

Security issues fixed:

- CVE-2017-17434: The daemon in rsync did not check for fnamecmp filenames in
 the daemon_filter_list data structure (in the recv_files function in
 receiver.c) and also did not apply the sanitize_paths protection mechanism to
 pathnames found in 'xname follows' strings (in the read_ndx_and_attrs function
 in rsync.c), which allowed remote attackers to bypass intended access
 restrictions' (bsc#1071460).
- CVE-2017-17433: The recv_files function in receiver.c in the daemon in rsync,
 proceeded with certain file metadata updates before checking for a filename in
 the daemon_filter_list data structure, which allowed remote attackers to bypass
 intended access restrictions (bsc#1071459).
- CVE-2017-16548: The receive_xattr function in xattrs.c in rsync did not check
 for a trailing '\\0' character in an xattr name, which allowed remote attackers
 to cause a denial of service (heap-based buffer over-read and application
 crash) or possibly have unspecified other impact by sending crafted data to the
 daemon (bsc#1066644).");

  script_tag(name:"affected", value:"'rsync' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.0.4~2.53.3.1", rls:"SLES11.0SP4"))) {
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
