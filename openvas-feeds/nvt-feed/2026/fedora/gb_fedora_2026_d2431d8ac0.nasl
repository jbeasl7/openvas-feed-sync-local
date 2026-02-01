# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.1002431100897990");
  script_tag(name:"creation_date", value:"2026-01-22 04:25:15 +0000 (Thu, 22 Jan 2026)");
  script_version("2026-01-23T05:49:25+0000");
  script_tag(name:"last_modification", value:"2026-01-23 05:49:25 +0000 (Fri, 23 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-d2431d8ac0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-d2431d8ac0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-d2431d8ac0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429390");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/draft-ietf-sidrops-rpki-ccr/");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/status-change-rpki-ghostbusters-record-to-historic/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpki-client' package(s) announced via the FEDORA-2026-d2431d8ac0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# rpki-client 9.7

- The Canonical Cache Representation underwent a breaking change after the adoption of [link moved to references] as a SIDROPS working group item. Apart from several CMS-related cosmetics it now uses a IANA-assigned content type. As a result, rpki-client 9.7 cannot parse rpki-client 9.6's `.ccr` files and vice versa.
- Support for Ghostbusters Record objects (RFC 6493) has been removed. Nobody showed interest in deploying this and there are other, widely supported ways of exchanging operational contact information such as RDAP. RFC 6493 is undergoing a status review to be marked as historic: [link moved to references]
- Prepare the code base for the opaque `ASN1_STRING` structure in OpenSSL 4.
- Fixed two reliability issues: one where a malicious RPKI Certification Authority can trigger a crash, one where malicious Trust Anchor can provoke memory exhaustion.");

  script_tag(name:"affected", value:"'rpki-client' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"rpki-client", rpm:"rpki-client~9.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpki-client-debuginfo", rpm:"rpki-client-debuginfo~9.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpki-client-debugsource", rpm:"rpki-client-debugsource~9.7~1.fc42", rls:"FC42"))) {
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
