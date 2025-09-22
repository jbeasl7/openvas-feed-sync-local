# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120011");
  script_cve_id("CVE-2014-6407", "CVE-2014-6408");
  script_tag(name:"creation_date", value:"2015-09-08 11:14:55 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-454)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-454");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-454.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the ALAS-2014-454 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Docker versions 1.3.0 through 1.3.1 allowed security options to be applied to images, allowing images to modify the default run profile of containers executing these images. This vulnerability could allow a malicious image creator to loosen the restrictions applied to a container's processes, potentially facilitating a break-out. (CVE-2014-6408)

The Docker engine, up to and including version 1.3.1, was vulnerable to extracting files to arbitrary paths on the host during 'docker pull' and 'docker load' operations. This was caused by symlink and hardlink traversals present in Docker's image extraction. This vulnerability could be leveraged to perform remote code execution and privilege escalation. (CVE-2014-6407)");

  script_tag(name:"affected", value:"'docker' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~1.3.2~1.0.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~1.3.2~1.0.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-pkg-devel", rpm:"docker-pkg-devel~1.3.2~1.0.amzn1", rls:"AMAZON"))) {
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
