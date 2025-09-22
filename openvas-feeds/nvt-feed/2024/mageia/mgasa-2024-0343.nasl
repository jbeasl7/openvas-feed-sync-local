# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0343");
  script_cve_id("CVE-2023-45290", "CVE-2024-1753", "CVE-2024-28176", "CVE-2024-28180", "CVE-2024-3727", "CVE-2024-6104", "CVE-2024-9341", "CVE-2024-9407");
  script_tag(name:"creation_date", value:"2024-11-04 04:11:34 +0000 (Mon, 04 Nov 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 15:15:41 +0000 (Mon, 18 Mar 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0343)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0343");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0343.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33036");
  script_xref(name:"URL", value:"https://github.com/containers/buildah/security/advisories/GHSA-pmf3-c36m-g5cf");
  script_xref(name:"URL", value:"https://github.com/containers/podman/security/advisories/GHSA-874v-pj72-92f3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CYT3D2P3OJKISNFKOOHGY6HCUCQZYAVR/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/MYMA7BZJZTURAPGKHV2ACU3HBJTKVYMK/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/PJ4RBOYLRKSRUVS77S4OAZ7SQJWH36K2/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-July/018858.html");
  script_xref(name:"URL", value:"https://lwn.net/Articles/978101/");
  script_xref(name:"URL", value:"https://lwn.net/Articles/978102/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah, podman, skopeo' package(s) announced via the MGASA-2024-0343 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in Buildah (and subsequently Podman Build) which allows
containers to mount arbitrary locations on the host filesystem into
build containers. A malicious Containerfile can use a dummy image with a
symbolic link to the root filesystem as a mount source and cause the
mount operation to mount the host root filesystem inside the RUN step.
The commands inside the RUN step will then have read-write access to the
host filesystem, allowing for full container escape at build time.
(CVE-2024-1753)
A flaw was found in the github.com/containers/image library. This flaw
allows attackers to trigger unexpected authenticated registry accesses
on behalf of a victim user, causing resource exhaustion, local path
traversal, and other attacks. (CVE-2024-3727)
When parsing a multipart form (either explicitly with
Request.ParseMultipartForm or implicitly with Request.FormValue,
Request.PostFormValue, or Request.FormFile), limits on the total size of
the parsed form were not applied to the memory consumed while reading a
single form line. This permits a maliciously crafted input containing
very long lines to cause allocation of arbitrarily large amounts of
memory, potentially leading to memory exhaustion. With fix, the
ParseMultipartForm function now correctly limits the maximum size of
form lines. (CVE-2023-45290)
Package jose aims to provide an implementation of the Javascript Object
Signing and Encryption set of standards. An attacker could send a JWE
containing compressed data that used large amounts of memory and CPU
when decompressed by Decrypt or DecryptMulti. Those functions now return
an error if the decompressed data would exceed 250kB or 10x the
compressed size (whichever is larger). This vulnerability has been
patched in versions 4.0.1, 3.0.3 and 2.6.3. (CVE-2024-28180)
jose is JavaScript module for JSON Object Signing and Encryption,
providing support for JSON Web Tokens (JWT), JSON Web Signature (JWS),
JSON Web Encryption (JWE), JSON Web Key (JWK), JSON Web Key Set (JWKS),
and more. A vulnerability has been identified in the JSON Web Encryption
(JWE) decryption interfaces, specifically related to the support for
decompressing plaintext after its decryption. Under certain conditions
it is possible to have the user's environment consume unreasonable
amount of CPU time or memory during JWE Decryption operations. This
issue has been patched in versions 2.0.7 and 4.15.5. (CVE-2024-28176)
A flaw was found in Go. When FIPS mode is enabled on a system, container
runtimes may incorrectly handle certain file paths due to improper
validation in the containers/common Go library. This flaw allows an
attacker to exploit symbolic links and trick the system into mounting
sensitive host directories inside a container. This issue also allows
attackers to access critical host files, bypassing the intended
isolation between containers and the host system. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'buildah, podman, skopeo' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.37.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-tests", rpm:"buildah-tests~1.37.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.9.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~4.9.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-fish-completion", rpm:"podman-fish-completion~4.9.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-gvproxy", rpm:"podman-gvproxy~4.9.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-plugins", rpm:"podman-plugins~4.9.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~4.9.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-zsh-completion", rpm:"podman-zsh-completion~4.9.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~1.16.1~1.mga9", rls:"MAGEIA9"))) {
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
