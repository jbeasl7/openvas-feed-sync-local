# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20904.1");
  script_cve_id("CVE-2025-11065", "CVE-2025-58181", "CVE-2026-22703", "CVE-2026-22772", "CVE-2026-23991", "CVE-2026-23992", "CVE-2026-24122", "CVE-2026-24137", "CVE-2026-26958");
  script_tag(name:"creation_date", value:"2026-04-03 04:47:54 +0000 (Fri, 03 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-17 16:02:19 +0000 (Tue, 17 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20904-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20904-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620904-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258612");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-April/025109.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cosign' package(s) announced via the SUSE-SU-2026:20904-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cosign fixes the following issues:

Update to version 3.0.5:

- CVE-2026-24122: Fixed improper validation of certificates that outlive
 expired CA certificates (bsc#1258542)
- CVE-2026-26958: Fixed filippo.io/edwards25519: failure to initialize receiver
 in MultiScalarMult can produce invalid results and lead to undefined behavior
 (bsc#1258612)
- CVE-2026-24137: Fixed github.com/sigstore/sigstore/pkg/tuf: legacy TUF client
 allows for arbitrary file writes with target cache path traversal
 (bsc#1257139)
- CVE-2026-22772: Fixed github.com/sigstore/fulcio: bypass MetaIssuer URL
 validation bypass can trigger SSRF to arbitrary internal services
 (bsc#1256562)
- CVE-2026-23991: Fixed github.com/theupdateframework/go-tuf/v2: denial of
 service due to invalid TUF metadata JSON returned by TUF repository
 (bsc#1257080)
- CVE-2026-23992: Fixed github.com/theupdateframework/go-tuf/v2: unauthorized
 modification to TUF metadata files due to a compromised or misconfigured TUF
 repository (bsc#1257085)
- CVE-2025-11065: Fixed github.com/go-viper/mapstructure/v2: sensitive
 Information leak in logs (bsc#1250620)
- CVE-2026-22703: Fixed that cosign verification accepts any valid Rekor entry
 under certain conditions (bsc#1256496)
- CVE-2025-58181: Fixed golang.org/x/crypto/ssh: invalidated number of
 mechanisms can cause unbounded memory consumption (bsc#1253913)");

  script_tag(name:"affected", value:"'cosign' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"cosign", rpm:"cosign~3.0.5~160000.1.1", rls:"SLES16.0.0"))) {
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
