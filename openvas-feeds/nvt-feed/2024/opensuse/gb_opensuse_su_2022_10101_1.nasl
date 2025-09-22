# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833820");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2020-15690", "CVE-2020-15692", "CVE-2020-15693", "CVE-2020-15694", "CVE-2021-21372", "CVE-2021-21373", "CVE-2021-21374", "CVE-2021-29495", "CVE-2021-41259");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-20 19:10:53 +0000 (Thu, 20 Aug 2020)");
  script_tag(name:"creation_date", value:"2024-03-04 07:13:16 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for nim (openSUSE-SU-2022:10101-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10101-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SNDISR45BBTIWW5MDTIQOSRHOEV3XUKF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nim'
  package(s) announced via the openSUSE-SU-2022:10101-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nim fixes the following issues:
  Includes upstream security fixes for:

  * (boo#1175333, CVE-2020-15693) httpClient is vulnerable to a CR-LF
       injection

  * (boo#1175334, CVE-2020-15692) mishandle of argument to
       browsers.openDefaultBrowser

  * (boo#1175332, CVE-2020-15694) httpClient.get().contentLength() fails to
       properly validate the server response

  * (boo#1192712, CVE-2021-41259) null byte accepted in getContent function,
       leading to URI validation bypass

  * (boo#1185948, CVE-2021-29495) stdlib httpClient does not validate peer
       certificates by default

  * (boo#1185085, CVE-2021-21374) Improper verification of the SSL/TLS
       certificate

  * (boo#1185084, CVE-2021-21373) 'nimble refresh' falls back to a non-TLS
       URL in case of error

  * (boo#1185083, CVE-2021-21372) doCmd can be leveraged to execute
       arbitrary commands

  * (boo#1181705, CVE-2020-15690) Standard library asyncftpclient lacks a
       check for newline character
  Update to 1.6.6

  * standard library use consistent styles for variable names so it can be
       used in projects which force a consistent style with

  - -styleCheck:usages option.

  * ARC/ORC are now considerably faster at method dispatching, bringing its
       performance back on the level of the refc memory management.

  * oids: switch from PRNG to random module

  * nimc.rst: fix table markup

  * nimRawSetjmp: support Windows

  * correctly enable chronos

  * bigints are not supposed to work on 1.2.x

  * disable nimpy

  * misc bugfixes

  * fixes a 'mixin' statement handling regression [backport:1.2");

  script_tag(name:"affected", value:"'nim' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"nim", rpm:"nim~1.6.6~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
