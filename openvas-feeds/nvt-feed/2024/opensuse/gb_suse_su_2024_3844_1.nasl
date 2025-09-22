# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856667");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-2199", "CVE-2024-3657", "CVE-2024-5953");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-28 13:15:11 +0000 (Tue, 28 May 2024)");
  script_tag(name:"creation_date", value:"2024-11-01 05:02:01 +0000 (Fri, 01 Nov 2024)");
  script_name("openSUSE: Security Advisory for 389 (SUSE-SU-2024:3844-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3844-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LBDQQIRQZTPUEWYWOWCXVAMG7LBXWQ5Y");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389'
  package(s) announced via the SUSE-SU-2024:3844-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for 389-ds fixes the following issues:

  * Persist extracted key path for ldap_ssl_client_init over repeat invocations
      (bsc#1230852)

  * Re-enable use of .dsrc basedn for dsidm commands (bsc#1231462)

  * Update to version 2.2.10~git18.20ce9289:

  * RFE: Use previously extracted key path

  * Update dsidm to prioritize basedn from .dsrc over interactive input

  * UI: Instance fails to load when DB backup directory doesn't exist

  * Improve online import robustness when the server is under load

  * Ensure all slapi_log_err calls end format strings with newline character \n

  * RFE: when memberof is enabled, defer updates of members from the update of
      the group

  * Provide more information in the error message during setup_ol_tls_conn()

  * Wrong set of entries returned for some search filters

  * Schema lib389 object is not keeping custom schema data upon editing

  * UI: Fix audit issue with npm - micromatch

  * Fix long delay when setting replication agreement with dsconf

  * Changelog trims updates from a given RID even if a consumer has not received
      any of them

  * test_password_modify_non_utf8 should set default password storage scheme

  * Update Cargo.lock

  * Rearrange includes for 32-bit support logic

  * Fix fedora cop RawHide builds

  * Bump braces from 3.0.2 to 3.0.3 in /src/cockpit/389-console

  * Enabling replication for a sub suffix crashes browser

  * d2entry - Could not open id2entry err 0 - at startup when having sub-
      suffixes

  * Slow ldif2db import on a newly created BDB backend

  * Audit log buffering doesn't handle large updates

  * RFE: improve the performance of evaluation of filter component when tested
      against a large valueset (like group members)

  * passwordHistory is not updated with a pre-hashed password

  * ns-slapd crash in referint_get_config

  * Fix the UTC offset print

  * Fix OpenLDAP version autodetection

  * RFE: add new operation note for MFA authentications

  * Add log buffering to audit log

  * Fix connection timeout error breaking errormap

  * Improve dsidm CLI No Such Entry handling

  * Improve connection timeout error logging

  * Add hidden -v and -j options to each CLI subcommand

  * Fix various issues with logconv.pl

  * Fix certificate lifetime displayed as NaN

  * Enhance Rust and JS bundling and add SPDX licenses for both

  * Remove audit-ci from dependencies

  * Fix unused variable warning from previous commit

  * covscan: fix memory leak in audit log when adding entries

  * Add a check for tagged commits

  * dscreat ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'389' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0-debuginfo", rpm:"libsvrcore0-debuginfo~2.2.10~git18.20ce9289~150600.8.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debuginfo", rpm:"389-ds-debuginfo~2.2.10~git18.20ce9289~150600.8.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debugsource", rpm:"389-ds-debugsource~2.2.10~git18.20ce9289~150600.8.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0", rpm:"libsvrcore0~2.2.10~git18.20ce9289~150600.8.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-snmp", rpm:"389-ds-snmp~2.2.10~git18.20ce9289~150600.8.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-devel", rpm:"389-ds-devel~2.2.10~git18.20ce9289~150600.8.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-snmp-debuginfo", rpm:"389-ds-snmp-debuginfo~2.2.10~git18.20ce9289~150600.8.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds", rpm:"389-ds~2.2.10~git18.20ce9289~150600.8.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389", rpm:"lib389~2.2.10~git18.20ce9289~150600.8.10.1", rls:"openSUSELeap15.6"))) {
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
