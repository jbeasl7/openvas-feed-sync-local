# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1471.1");
  script_cve_id("CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7974", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551", "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 13:53:53 +0000 (Tue, 15 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1471-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1471-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161471-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977464");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-June/002089.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2016:1471-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ntp fixes the following issues:

- Separate the creation of ntp.keys and key #1 in it to avoid
 problems when upgrading installations that have the file, but
 no key #1, which is needed e.g. by 'rcntp addserver'.

- Update to 4.2.8p7 (bsc#977446):
 * CVE-2016-1547, bsc#977459:
 Validate crypto-NAKs, AKA: CRYPTO-NAK DoS.
 * CVE-2016-1548, bsc#977461: Interleave-pivot
 * CVE-2016-1549, bsc#977451:
 Sybil vulnerability: ephemeral association attack.
 * CVE-2016-1550, bsc#977464: Improve NTP security against buffer
 comparison timing attacks.
 * CVE-2016-1551, bsc#977450:
 Refclock impersonation vulnerability
 * CVE-2016-2516, bsc#977452: Duplicate IPs on unconfig
 directives will cause an assertion botch in ntpd.
 * CVE-2016-2517, bsc#977455: remote configuration trustedkey/
 requestkey/controlkey values are not properly validated.
 * CVE-2016-2518, bsc#977457: Crafted addpeer with hmode > 7
 causes array wraparound with MATCH_ASSOC.
 * CVE-2016-2519, bsc#977458: ctl_getitem() return value not
 always checked.
 * integrate ntp-fork.patch
 * Improve the fixes for:
 CVE-2015-7704, CVE-2015-7705, CVE-2015-7974
- Restrict the parser in the startup script to the first
 occurrance of 'keys' and 'controlkey' in ntp.conf (bsc#957226).");

  script_tag(name:"affected", value:"'ntp' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p7~44.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p7~44.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p7~44.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p7~44.1", rls:"SLES11.0SP3"))) {
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
