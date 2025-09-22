# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02592.1");
  script_cve_id("CVE-2025-46569");
  script_tag(name:"creation_date", value:"2025-08-04 04:31:53 +0000 (Mon, 04 Aug 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02592-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02592-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502592-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246725");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041004.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cosign' package(s) announced via the SUSE-SU-2025:02592-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cosign fixes the following issues:

Update to version 2.5.3 (jsc#SLE-23879):

- CVE-2025-46569: Fixed OPA server Data API HTTP path injection of Rego (bsc#1246725)

Changelog:

Update to 2.5.3:

- Add signing-config create command (#4280)
- Allow multiple services to be specified for trusted-root create (#4285)
- force when copying the latest image to overwrite (#4298)
- Fix cert verification logic for trusted-root/SCTs (#4294)
- Fix lint error for types package (#4295)
- feat: Add OCI 1.1+ experimental support to tree (#4205)
- Add validity period end for trusted-root create (#4271)
- avoid double-loading trustedroot from file (#4264)

Update to 2.5.2:

- Do not load trusted root when CT env key is set
- docs: improve doc for --no-upload option (#4206)

Update to 2.5.1:

- Add Rekor v2 support for trusted-root create (#4242)
- Add baseUrl and Uri to trusted-root create command
- Upgrade to TUF v2 client with trusted root
- Don't verify SCT for a private PKI cert (#4225)
- Bump TSA library to relax EKU chain validation rules (#4219)
- Bump sigstore-go to pick up log index=0 fix (#4162)
- remove unused recursive flag on attest command (#4187)");

  script_tag(name:"affected", value:"'cosign' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"cosign", rpm:"cosign~2.5.3~150400.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cosign", rpm:"cosign~2.5.3~150400.3.30.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"cosign", rpm:"cosign~2.5.3~150400.3.30.1", rls:"SLES15.0SP6"))) {
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
