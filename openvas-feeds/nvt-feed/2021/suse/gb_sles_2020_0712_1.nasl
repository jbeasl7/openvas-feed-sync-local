# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0712.1");
  script_cve_id("CVE-2019-10214");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-18 18:15:45 +0000 (Wed, 18 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0712-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0712-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200712-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'skopeo' package(s) announced via the SUSE-SU-2020:0712-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for skopeo fixes the following issues:

Update to skopeo v0.1.41 (bsc#1165715):
Bump github.com/containers/image/v5 from 5.2.0 to 5.2.1

Bump gopkg.in/yaml.v2 from 2.2.7 to 2.2.8

Bump github.com/containers/common from 0.0.7 to 0.1.4

Remove the reference to openshift/api

vendor github.com/containers/image/v5@v5.2.0

Manually update buildah to v1.13.1

add specific authfile options to copy (and sync) command.

Bump github.com/containers/buildah from 1.11.6 to 1.12.0

Add context to --encryption-key / --decryption-key processing failures

Bump github.com/containers/storage from 1.15.2 to 1.15.3

Bump github.com/containers/buildah from 1.11.5 to 1.11.6

remove direct reference on c/image/storage

Makefile: set GOBIN

Bump gopkg.in/yaml.v2 from 2.2.2 to 2.2.7

Bump github.com/containers/storage from 1.15.1 to 1.15.2

Introduce the sync command

openshift cluster: remove .docker directory on teardown

Bump github.com/containers/storage from 1.14.0 to 1.15.1

document installation via apk on alpine

Fix typos in doc for image encryption

Image encryption/decryption support in skopeo

make vendor-in-container

Bump github.com/containers/buildah from 1.11.4 to 1.11.5

Travis: use go v1.13

Use a Windows Nano Server image instead of Server Core for multi-arch
 testing

Increase test timeout to 15 minutes

Run the test-system container without --net=host

Mount /run/systemd/journal/socket into test-system containers

Don't unnecessarily filter out vendor from (go list ./...)
 output

Use -mod=vendor in (go {list,test,vet})

Bump github.com/containers/buildah from 1.8.4 to 1.11.4

Bump github.com/urfave/cli from 1.20.0 to 1.22.1

skopeo: drop support for ostree

Don't critically fail on a 403 when listing tags

Revert 'Temporarily work around auth.json location confusion'

Remove references to atomic

Remove references to storage.conf

Dockerfile: use golang-github-cpuguy83-go-md2man

bump version to v0.1.41-dev

systemtest: inspect container image different from current platform arch

Changes in v0.1.40:
vendor containers/image v5.0.0

copy: add a --all/-a flag

System tests: various fixes

Temporarily work around auth.json location confusion

systemtest: copy: docker->storage->oci-archive

systemtest/010-inspect.bats: require only PATH

systemtest: add simple env test in inspect.bats

bash completion: add comments to keep scattered options in sync

bash completion: use read -r instead of disabling SC2207

bash completion: support --opt arg completion

bash-completion: use replacement instead of sed

bash completion: disable shellcheck SC2207

bash completion: double-quote to avoid re-splitting

bash completions: use bash replacement instead of sed

bash completion: remove unused variable

bash-completions: split decl and assignment to avoid masking retvals

bash completion: double-quote fixes

bash completion: hard-set PROG=skopeo

bash completion: remove unused ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'skopeo' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~0.1.41~4.11.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-debuginfo", rpm:"skopeo-debuginfo~0.1.41~4.11.1", rls:"SLES15.0SP1"))) {
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
