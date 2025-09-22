# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.4781.2");
  script_cve_id("CVE-2016-10030", "CVE-2018-10995");
  script_tag(name:"creation_date", value:"2023-02-02 04:10:35 +0000 (Thu, 02 Feb 2023)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-05 19:44:19 +0000 (Thu, 05 Jan 2017)");

  script_name("Ubuntu: Security Advisory (USN-4781-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4781-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4781-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm-llnl' package(s) announced via the USN-4781-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4781-1 fixed several vulnerabilities in Slurm. This update provides
the corresponding updates for Ubuntu 14.04 ESM (CVE-2016-10030) and
Ubuntu 16.04 ESM (CVE-2018-10995).

Original advisory details:

 It was discovered that Slurm incorrectly handled certain messages
 between the daemon and the user. An attacker could possibly use this
 issue to assume control of an arbitrary file on the system. This
 issue only affected Ubuntu 16.04 ESM.
 (CVE-2016-10030)

 It was discovered that Slurm mishandled SPANK environment variables.
 An attacker could possibly use this issue to gain elevated privileges.
 This issue only affected Ubuntu 16.04 ESM. (CVE-2017-15566)

 It was discovered that Slurm mishandled certain SQL queries. A local
 attacker could use this issue to gain elevated privileges. This
 issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM and
 Ubuntu 18.04 ESM. (CVE-2018-7033)

 It was discovered that Slurm mishandled user names and group ids. A local
 attacker could use this issue to gain administrative privileges.
 This issue only affected Ubuntu 14.04 ESM and Ubuntu 18.04 ESM.
 (CVE-2018-10995)

 It was discovered that Slurm mishandled 23-bit systems. A local attacker
 could use this to gain administrative privileges. This issue only affected
 Ubuntu 14.04 ESM, Ubuntu 16.04 ESM and Ubuntu 18.04 ESM. (CVE-2019-6438)

 It was discovered that Slurm incorrectly handled certain inputs
 when Message Aggregation is enabled. An attacker could possibly
 use this issue to launch a process as an arbitrary user.
 This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM
 and Ubuntu 20.04 ESM. (CVE-2020-12693)

 It was discovered that Slurm incorrectly handled certain RPC inputs.
 An attacker could possibly use this issue to execute arbitrary code.
 This issue only affected Ubuntu 18.04 ESM and Ubuntu 20.04 ESM.
 (CVE-2020-27745)

 Jonas Stare discovered that Slurm exposes sensitive information related
 to the X protocol. An attacker could possibly use this issue to obtain
 a graphical session from an arbitrary user. This issue only affected
 Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-27746)

 It was discovered that Slurm incorrectly handled environment parameters.
 An attacker could possibly use this issue to execute arbitrary code.
 (CVE-2021-31215)");

  script_tag(name:"affected", value:"'slurm-llnl' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-slurm", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpmi0", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm-perl", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm26", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurmdb-perl", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurmdb26", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl-basic-plugins", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl-slurmdbd", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl-sview", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl-torque", ver:"2.6.5-1ubuntu0.1~esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-slurm", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpmi0", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm-perl", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm29", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurmdb-perl", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurmdb29", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client-emulator", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl-slurmdbd", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-emulator", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-torque", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmctld", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmd", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmdbd", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sview", ver:"15.08.7-1ubuntu0.1~esm5", rls:"UBUNTU16.04 LTS"))) {
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
