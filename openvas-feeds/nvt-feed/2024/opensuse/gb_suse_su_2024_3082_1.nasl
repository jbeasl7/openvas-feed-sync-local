# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856413");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-2199", "CVE-2024-3657", "CVE-2024-5953");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-28 13:15:11 +0000 (Tue, 28 May 2024)");
  script_tag(name:"creation_date", value:"2024-09-04 04:00:37 +0000 (Wed, 04 Sep 2024)");
  script_name("openSUSE: Security Advisory for 389 (SUSE-SU-2024:3082-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3082-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CMDI7FHO2PDBEOWE4ASE6YMNE4SWFGQV");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389'
  package(s) announced via the SUSE-SU-2024:3082-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for 389-ds fixes the following issues:

  Security issues fixed:

  * CVE-2024-3657: Fixed potential denial of service via specially crafted
      kerberos AS-REQ request (bsc#1225512)

  * CVE-2024-5953: Fixed a denial of service caused by malformed userPassword
      hashes (bsc#1226277)

  * CVE-2024-2199: Fixed a crash caused by malformed userPassword in do_modify()
      (bsc#1225507)

  Non-security issues fixed:

  * crash when user does change password using iso-8859-1 encoding (bsc#1228912)

  * Update to version 2.2.10~git2.345056d3:

  * Issue 2324 - Add a CI test (#6289)

  * Issue 6284 - BUG - freelist ordering causes high wtime

  * Update to version 2.2.10~git0.4d7218b7:

  * Bump version to 2.2.10

  * Issue 5327 - Fix test metadata

  * Issue 5853 - Update Cargo.lock

  * Issue 5962 - Rearrange includes for 32-bit support logic

  * Issue 5973 - Fix fedora cop RawHide builds (#5974)

  * Bump braces from 3.0.2 to 3.0.3 in /src/cockpit/389-console

  * Issue 6254 - Enabling replication for a sub suffix crashes browser (#6255)

  * Issue 6224 - d2entry - Could not open id2entry err 0 - at startup when
      having sub-suffixes (#6225)

  * Issue 6183 - Slow ldif2db import on a newly created BDB backend (#6208)

  * Issue 6170 - audit log buffering doesn't handle large updates

  * Issue 6193 - Test failure: test_tls_command_returns_error_text

  * Issue 6189 - CI tests fail with `[Errno 2] No such file or directory:
      &#x27 /var/cache/dnf/metadata_lock.pid&#x27 `

  * Issue 6172 - RFE: improve the performance of evaluation of filter component
      when tested against a large valueset (like group members) (#6173)

  * Issue 6092 - passwordHistory is not updated with a pre-hashed password
      (#6093)

  * Issue 6080 - ns-slapd crash in referint_get_config (#6081)

  * Issue 6117 - Fix the UTC offset print (#6118)

  * Issue 5305 - OpenLDAP version autodetection doesn't work

  * Issue 6112 - RFE - add new operation note for MFA authentications

  * Issue 5842 - Add log buffering to audit log

  * Issue 6103 - New connection timeout error breaks errormap (#6104)

  * Issue 6067 - Improve dsidm CLI No Such Entry handling (#6079)

  * Issue 6096 - Improve connection timeout error logging (#6097)

  * Issue 6067 - Add hidden -v and -j options to each CLI subcommand (#6088)

  * Issue 5487 - Fix various issues with logconv.pl (#6085)

  ##");

  script_tag(name:"affected", value:"'389' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"389-ds-2.2.10", rpm:"389-ds-2.2.10~git2.345056d3~150500.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debugsource-2.2.10", rpm:"389-ds-debugsource-2.2.10~git2.345056d3~150500.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0-2.2.10-git2.345056d3", rpm:"libsvrcore0-2.2.10-git2.345056d3~150500.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-snmp-2.2.10", rpm:"389-ds-snmp-2.2.10~git2.345056d3~150500.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-snmp-debuginfo", rpm:"389-ds-snmp-debuginfo~2.2.10~git2.345056d3~150500.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debuginfo-2.2.10", rpm:"389-ds-debuginfo-2.2.10~git2.345056d3~150500.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0-debuginfo-2.2.10", rpm:"libsvrcore0-debuginfo-2.2.10~git2.345056d3~150500.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-devel-2.2.10", rpm:"389-ds-devel-2.2.10~git2.345056d3~150500.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-2.2.1", rpm:"lib389-2.2.10~git2.345056d3~150500.3.21.1", rls:"openSUSELeap15.5"))) {
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
