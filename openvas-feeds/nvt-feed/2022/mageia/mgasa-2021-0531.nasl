# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0531");
  script_cve_id("CVE-2021-41190");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-22 14:59:26 +0000 (Mon, 22 Nov 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0531)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0531");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0531.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29669");
  script_xref(name:"URL", value:"https://github.com/moby/moby/security/advisories/GHSA-xmmx-7jpf-fx42");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-containerd' package(s) announced via the MGASA-2021-0531 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The OCI Distribution Spec project defines an API protocol to facilitate
and standardize the distribution of content. In the OCI Distribution
Specification version 1.0.0 and prior, the Content-Type header alone was
used to determine the type of document during push and pull operations.
Documents that contain both 'manifests' and 'layers' fields could be
interpreted as either a manifest or an index in the absence of an
accompanying Content-Type header. If a Content-Type header changed between
two pulls of the same digest, a client may interpret the resulting content
differently. The OCI Distribution Specification has been updated to require
that a mediaType value present in a manifest or index match the
Content-Type header used during the push and pull operations. Clients
pulling from a registry may distrust the Content-Type header and reject an
ambiguous document that contains both 'manifests' and 'layers' fields or
'manifests' and 'config' fields if they are unable to update to version
1.0.1 of the spec.");

  script_tag(name:"affected", value:"'docker-containerd' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"docker-containerd", rpm:"docker-containerd~1.5.8~1.mga8", rls:"MAGEIA8"))) {
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
