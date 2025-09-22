# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833373");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-38201");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-05 19:13:35 +0000 (Tue, 05 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:05:38 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for keylime (SUSE-SU-2023:3525-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3525-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LEQH7IKKG7OE6AI7XHRPSD3WC3UOYMTU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keylime'
  package(s) announced via the SUSE-SU-2023:3525-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for keylime fixes the following issues:

  * CVE-2023-38201: Fixed a bug to avoid leaks of the authorization tag.
      (bsc#1213314)

  ##");

  script_tag(name:"affected", value:"'keylime' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"keylime-config", rpm:"keylime-config~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent", rpm:"keylime-agent~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-tpm_cert_store", rpm:"keylime-tpm_cert_store~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-keylime", rpm:"python3-keylime~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-verifier", rpm:"keylime-verifier~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-registrar", rpm:"keylime-registrar~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-logrotate", rpm:"keylime-logrotate~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-firewalld", rpm:"keylime-firewalld~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-config", rpm:"keylime-config~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent", rpm:"keylime-agent~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-tpm_cert_store", rpm:"keylime-tpm_cert_store~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-keylime", rpm:"python3-keylime~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-verifier", rpm:"keylime-verifier~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-registrar", rpm:"keylime-registrar~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-logrotate", rpm:"keylime-logrotate~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-firewalld", rpm:"keylime-firewalld~6.3.2~150400.4.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"keylime-config", rpm:"keylime-config~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent", rpm:"keylime-agent~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-tpm_cert_store", rpm:"keylime-tpm_cert_store~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-keylime", rpm:"python3-keylime~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-verifier", rpm:"keylime-verifier~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-registrar", rpm:"keylime-registrar~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-logrotate", rpm:"keylime-logrotate~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-firewalld", rpm:"keylime-firewalld~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-config", rpm:"keylime-config~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent", rpm:"keylime-agent~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-tpm_cert_store", rpm:"keylime-tpm_cert_store~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-keylime", rpm:"python3-keylime~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-verifier", rpm:"keylime-verifier~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-registrar", rpm:"keylime-registrar~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-logrotate", rpm:"keylime-logrotate~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-firewalld", rpm:"keylime-firewalld~6.3.2~150400.4.20.1", rls:"openSUSELeap15.5"))) {
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