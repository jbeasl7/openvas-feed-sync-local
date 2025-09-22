# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705283");
  script_cve_id("CVE-2020-36518", "CVE-2022-42003", "CVE-2022-42004");
  script_tag(name:"creation_date", value:"2022-11-18 02:00:06 +0000 (Fri, 18 Nov 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-04 18:56:31 +0000 (Tue, 04 Oct 2022)");

  script_name("Debian: Security Advisory (DSA-5283-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5283-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5283-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5283");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/jackson-databind");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jackson-databind' package(s) announced via the DSA-5283-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws were discovered in jackson-databind, a fast and powerful JSON library for Java.

CVE-2020-36518

Java StackOverflow exception and denial of service via a large depth of nested objects.

CVE-2022-42003

In FasterXML jackson-databind resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled.

CVE-2022-42004

In FasterXML jackson-databind resource exhaustion can occur because of a lack of a check in BeanDeserializerBase.deserializeFromArray to prevent use of deeply nested arrays. An application is vulnerable only with certain customized choices for deserialization.

For the stable distribution (bullseye), these problems have been fixed in version 2.12.1-1+deb11u1.

We recommend that you upgrade your jackson-databind packages.

For the detailed security status of jackson-databind please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'jackson-databind' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libjackson2-databind-java", ver:"2.12.1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjackson2-databind-java-doc", ver:"2.12.1-1+deb11u1", rls:"DEB11"))) {
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
