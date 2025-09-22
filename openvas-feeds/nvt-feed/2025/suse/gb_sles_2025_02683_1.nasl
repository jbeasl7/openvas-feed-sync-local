# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02683.1");
  script_cve_id("CVE-2024-42516", "CVE-2024-43204", "CVE-2024-47252", "CVE-2025-23048", "CVE-2025-49630", "CVE-2025-49812", "CVE-2025-53020");
  script_tag(name:"creation_date", value:"2025-08-06 04:27:26 +0000 (Wed, 06 Aug 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02683-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02683-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502683-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246477");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041072.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2025:02683-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2 fixes the following issues:

- CVE-2024-42516: Fixed HTTP response splitting. (bsc#1246477)
- CVE-2024-43204: Fixed a SSRF when mod_proxy is loaded that allows an attacker to send outbound proxy requests to a URL controlled by them. (bsc#1246305)
- CVE-2024-47252: Fixed insufficient escaping of user-supplied data in mod_ssl allows an untrusted SSL/TLS client to insert escape characters into log file. (bsc#1246303)
- CVE-2025-23048: Fixed access control bypass by trusted clients through TLS 1.3 session resumption in some mod_ssl configurations. (bsc#1246302)
- CVE-2025-49630: Fixed denial of service can be triggered by untrusted clients causing an assertion in mod_proxy_http2. (bsc#1246307)
- CVE-2025-49812: Fixed Opossum Attack Application Layer Desynchronization using Opportunistic TLS. (bsc#1246169)
- CVE-2025-53020: Fixed HTTP/2 denial of service due to late release of memory after effective lifetime. (bsc#1246306)");

  script_tag(name:"affected", value:"'apache2' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.4.51~150200.3.82.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-devel", rpm:"apache2-devel~2.4.51~150200.3.82.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.4.51~150200.3.82.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.4.51~150200.3.82.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.4.51~150200.3.82.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.4.51~150200.3.82.1", rls:"SLES15.0SP3"))) {
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
