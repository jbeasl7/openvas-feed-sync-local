# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3540.1");
  script_cve_id("CVE-2016-10012", "CVE-2016-10708", "CVE-2017-15906", "CVE-2018-15473", "CVE-2018-15919");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:35 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-05 19:49:38 +0000 (Thu, 05 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3540-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3540-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183540-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106726");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004804.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2018:3540-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssh fixes the following issues:

Security issues fixed:

- CVE-2018-15919: Remotely observable behaviour in auth-gss2.c in OpenSSH could be used by remote attackers to detect existence of users on a target system when GSS2 is in use. OpenSSH developers do not want to treat such a username enumeration (or 'oracle') as a vulnerability. (bsc#1106163)
- CVE-2017-15906: The process_open function in sftp-server.c in OpenSSH did not properly prevent write operations in readonly mode, which allowed attackers to create zero-length files. (bsc#1065000, bsc#1106726)
- CVE-2016-10708: sshd allowed remote attackers to cause a denial of service (NULL pointer dereference and daemon crash) via an out-of-sequence NEWKEYS message, as demonstrated by Honggfuzz, related to kex.c and packet.c. (bsc#1076957)
- CVE-2018-15473: OpenSSH was prone to a user existance oracle vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c. (bsc#1105010)
- CVE-2016-10012: Removed pre-auth compression support from the server to prevent possible cryptographic attacks. (bsc#1016370)

Bugs fixed:

- Fixed failing 'AuthorizedKeysCommand' within a 'Match User' block in sshd_config (bsc#1105180)");

  script_tag(name:"affected", value:"'openssh' package(s) on SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.2p2~0.41.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.2p2~0.41.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~6.2p2~0.41.5.1", rls:"SLES11.0SP3"))) {
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
