# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885830");
  script_version("2024-03-14T05:06:59+0000");
  script_cve_id("CVE-2023-46009", "CVE-2023-44821");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-03-14 05:06:59 +0000 (Thu, 14 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-25 01:25:01 +0000 (Wed, 25 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-02 02:03:54 +0000 (Sat, 02 Mar 2024)");
  script_name("Fedora: Security Advisory for gifsicle (FEDORA-2024-4672c1ff2d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-4672c1ff2d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3I6Z7VAHUYX3Q4DULJ76NFD2CIFZJYH5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gifsicle'
  package(s) announced via the FEDORA-2024-4672c1ff2d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gifsicle is a command-line tool for creating, editing, and getting
information about GIF images and animations.

Some more gifsicle features:

  * Batch mode for changing GIFs in place.

  * Prints detailed information about GIFs, including comments.

  * Control over interlacing, comments, looping, transparency...

  * Creates well-behaved GIFs: removes redundant colors, only uses local
      color tables if it absolutely has to (local color tables waste space
      and can cause viewing artifacts), etc.

  * It can shrink colormaps and change images to use the Web-safe palette
      (or any colormap you choose).

  * It can optimize your animations! This stores only the changed portion
      of each frame, and can radically shrink your GIFs. You can also use
      transparency to make them even smaller. Gifsicle?s optimizer is pretty
      powerful, and usually reduces animations to within a couple bytes of
      the best commercial optimizers.

  * Unoptimizing animations, which makes them easier to edit.

  * A dumb-ass name.

One other program is included with gifsicle
and gifdiff compares two GIFs for identical visual appearance.");

  script_tag(name:"affected", value:"'gifsicle' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"gifsicle", rpm:"gifsicle~1.95~1.fc38", rls:"FC38"))) {
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