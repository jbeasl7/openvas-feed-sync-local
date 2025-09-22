# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.99597102991009732");
  script_cve_id("CVE-2024-35164");
  script_tag(name:"creation_date", value:"2025-07-04 04:10:25 +0000 (Fri, 04 Jul 2025)");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-09 15:24:36 +0000 (Wed, 09 Jul 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-c597fcda32)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-c597fcda32");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-c597fcda32");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2363860");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2375882");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2375935");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'guacamole-server' package(s) announced via the FEDORA-2025-c597fcda32 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Apache Guacamole 1.6.0

## User interface / platform
 * Add the ability to specify separate permissions for 'History' and 'Active sessions' tabs (GUACAMOLE-538)
 * Support batch import of connections from CSV (GUACAMOLE-926)
 * Add parameter token for connection name (GUACAMOLE-1177)
 * Provide audit log for system modifications (GUACAMOLE-1224)
 * Configurable username case sensitivity (GUACAMOLE-1239)
 * Provide chunked file upload mechanism (GUACAMOLE-1320)
 * Display whether user groups are disabled in group list (GUACAMOLE-1479)
 * Support for true fullscreen mode and keyboard lock (GUACAMOLE-1525)
 * Allow branding/customization of the section headers on the user home page (GUACAMOLE-1584)
 * Add support for specifying VNC 'encodings' parameter in webapp UI (GUACAMOLE-1642)
 * Automatically clear view if session expires in background (GUACAMOLE-1744)
 * Base64 encoding of image/binary data results in excessive syscalls that can degrade performance (GUACAMOLE-1776)
 * Update session recording playback progress during large frame gaps (GUACAMOLE-1803)
 * Enable viewing / searching of key events in session recording playback (GUACAMOLE-1820)
 * Improvements to the 'Recent connections' section (GUACAMOLE-1866)
 * History Recording Player should indicate points of interest (GUACAMOLE-1876)
 * Enhance client custom field functionality (GUACAMOLE-1904)
 * Provide notification, jump-to-top of page for a clone operation (GUACAMOLE-1916)
 * Bug: Logging of request details fails with recent Tomcat (GUACAMOLE-2052)

## Authentication, integration, and storage
 * Ensure `GUAC_DATE`/`GUAC_TIME` tokens match connection startDate (GUACAMOLE-61)
 * Add Proxy Hostname and Port to LDAP Extension (GUACAMOLE-577)
 * Add webapp support for smart card authentication (GUACAMOLE-839)
 * Enforce rate limit on authentication attempts (GUACAMOLE-990)
 * Broadly configurable time limits for user logins and connection usage (GUACAMOLE-1020)
 * Randomize generation of TOTP key until enrollment is confirmed (GUACAMOLE-1068)
 * Allow TOTP to be disabled by group membership (GUACAMOLE-1219)
 * Update guacamole-auth-duo to 'Duo Web v4 SDK' (GUACAMOLE-1289)
 * SAML module should be able to encrypt and sign requests (GUACAMOLE-1372)
 * Allow LDAP extension to configure TLS level (GUACAMOLE-1488)
 * Clarify TOTP reset/status logic (GUACAMOLE-1550)
 * Allow JDBC Auth Extensions to track history for external connections (GUACAMOLE-1616)
 * Allow extraction of 'domain' token from vault extensions (GUACAMOLE-1623)
 * Enable more granular vault associations (GUACAMOLE-1629)
 * Allow use of KSM one-time tokens in guacamole-vault-ksm extension (GUACAMOLE-1643)
 * Allow per-user KSM Vault configurations (GUACAMOLE-1656)
 * KSM vault extension should allow searching records by domain (GUACAMOLE-1661)
 * Allow user to configure Keeper Secrets Manager call frequency (GUACAMOLE-1722)
 * Enforce user access ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'guacamole-server' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"guacamole-server", rpm:"guacamole-server~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"guacamole-server-debuginfo", rpm:"guacamole-server-debuginfo~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"guacamole-server-debugsource", rpm:"guacamole-server-debugsource~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"guacd", rpm:"guacd~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"guacd-debuginfo", rpm:"guacd-debuginfo~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac", rpm:"libguac~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-client-kubernetes", rpm:"libguac-client-kubernetes~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-client-kubernetes-debuginfo", rpm:"libguac-client-kubernetes-debuginfo~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-client-rdp", rpm:"libguac-client-rdp~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-client-rdp-debuginfo", rpm:"libguac-client-rdp-debuginfo~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-client-ssh", rpm:"libguac-client-ssh~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-client-ssh-debuginfo", rpm:"libguac-client-ssh-debuginfo~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-client-telnet", rpm:"libguac-client-telnet~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-client-telnet-debuginfo", rpm:"libguac-client-telnet-debuginfo~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-client-vnc", rpm:"libguac-client-vnc~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-client-vnc-debuginfo", rpm:"libguac-client-vnc-debuginfo~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-debuginfo", rpm:"libguac-debuginfo~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguac-devel", rpm:"libguac-devel~1.6.0~1.fc41", rls:"FC41"))) {
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
