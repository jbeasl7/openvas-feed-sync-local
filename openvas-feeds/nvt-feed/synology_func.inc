# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Takes the build number argument and returns a full version based on the release notes from
#        https://www.synology.com/en-us/releaseNote/SRM
#
# @param buildNumber the build number of the release
#
# @return A string containing the full version
#
# @note This mapping is based on intervals of builds numbers. Rather than using the greatest build number for a certain version,
#       it is using the smallest build number of the next version, as exclusive upper limit.
#
function synology_srm_build_number_to_full_version( buildNumber ) {

  local_var buildNumber, int_ver;

  # nb: No "!buildNumber" because there might be also a build number of "0" (if that can ever happen)
  if( isnull( buildNumber ) )
    return NULL;

  int_ver = int( buildNumber );
  if( int_ver < 6007 )
    return "1.0-" + buildNumber;
  if( int_ver < 6022 )
    return "1.0.1-" + buildNumber;
  if( int_ver < 6030 )
    return "1.0.2-" + buildNumber;
  if( int_ver < 6338 )
    return "1.0.3-" + buildNumber;
  if( int_ver < 6414 )
    return "1.1-" + buildNumber;
  if( int_ver < 6425 )
    return "1.1.1-" + buildNumber;
  if( int_ver < 6447 )
    return "1.1.2-" + buildNumber;
  if( int_ver < 6509 )
    return "1.1.3-" + buildNumber;
  if( int_ver < 6542 )
    return "1.1.4-" + buildNumber;
  if( int_ver < 6931 )
    return "1.1.5-" + buildNumber;
  if( int_ver < 6941 )
    return "1.1.6-" + buildNumber;
  if( int_ver < 7742 )
    return "1.1.7-" + buildNumber;
  if( int_ver < 7779 )
    return "1.2-" + buildNumber;
  if( int_ver < 7915 )
    return "1.2.1-" + buildNumber;
  if( int_ver < 8017 )
    return "1.2.2-" + buildNumber;
  if( int_ver < 8081 )
    return "1.2.3-" + buildNumber;
  if( int_ver < 8225 )
    return "1.2.4-" + buildNumber;
  if( int_ver < 9193 )
    return "1.2.5-" + buildNumber;
  if( int_ver < 9346 )
    return "1.3-" + buildNumber;

  return "1.3.1-" + buildNumber;
}

# @brief Takes the build number argument and returns a full version based on the release notes from
#        https://www.synology.com/en-us/releaseNote/DSM

# @param buildNumber the build number of the release
#
# @return A string containing the full version
#
# @note This mapping is based on intervals of builds numbers. Rather than using the greatest build number for a certain version,
#       it is using the smallest build number of the next version, as exclusive upper limit.
#       The decision to do it this way came from the fact that, 4.3-3827 Update 8 is the last release for 4.3 in the Release Notes,
#       but actually there were targets with 4.3-4244
function synology_dsm_build_number_to_full_version( buildNumber ) {

  local_var buildNumber, int_ver;
  # nb: No "!buildNumber" because there might be also a build number of "0" (if that can ever happen)
  if( isnull( buildNumber ) )
    return NULL;

  int_ver = int( buildNumber );
  if( int_ver < 318 )
    return "1.0-" + buildNumber;
  if( int_ver < 832 )
    return "2.0-" + buildNumber;
  if( int_ver < 942 )
    return "2.1-" + buildNumber;
  if( int_ver < 1139 )
    return "2.2-" + buildNumber;
  if( int_ver < 1334 )
    return "2.3-" + buildNumber;
  if( int_ver < 1594 )
    return "3.0-" + buildNumber;
  if( int_ver < 1922 )
    return "3.1-" + buildNumber;
  if( int_ver < 2197 )
    return "3.2-" + buildNumber;
  if( int_ver < 2636 )
    return "4.0-" + buildNumber;
  if( int_ver < 3202 )
    return "4.1-" + buildNumber;
  if( int_ver < 3776 )
    return "4.2-" + buildNumber;
  if( int_ver < 4458 )
    return "4.3-" + buildNumber;
  if( int_ver < 5004 )
    return "5.0-" + buildNumber;
  if( int_ver < 5565 )
    return "5.1-" + buildNumber;
  if( int_ver < 7321 )
    return "5.2-" + buildNumber;
  if( int_ver < 7393 )
    return "6.0-" + buildNumber;
  if( int_ver < 8451 )
    return "6.0.1-" + buildNumber;
  if( int_ver < 8754 )
    return "6.0.2-" + buildNumber;
  if( int_ver < 15022 )
    return "6.0.3-" + buildNumber;
  if( int_ver < 15095 )
    return "6.1-" + buildNumber;
  if( int_ver < 15132 )
    return "6.1.1-" + buildNumber;
  if( int_ver < 15152 )
    return "6.1.2-" + buildNumber;
  if( int_ver < 15217 )
    return "6.1.3-" + buildNumber;
  if( int_ver < 15254 )
    return "6.1.4-" + buildNumber;
  if( int_ver < 15266 )
    return "6.1.5-" + buildNumber;
  if( int_ver < 15284 )
    return "6.1.6-" + buildNumber;
  if( int_ver < 23739 )
    return "6.1.7-" + buildNumber;
  if( int_ver < 23824 )
    return "6.2-" + buildNumber;
  if( int_ver < 24922 )
    return "6.2.1-" + buildNumber;
  if( int_ver < 25423 )
    return "6.2.2-" + buildNumber;
  if( int_ver < 25556 )
    return "6.2.3-" + buildNumber;
  if( int_ver < 41890 )
    return "6.2.4-" + buildNumber;
  if( int_ver < 42218 )
    return "7.0-" + buildNumber;
  if( int_ver < 42661 )
    return "7.0.1-" + buildNumber;
  if( int_ver < 42962 )
    return "7.1-" + buildNumber;
  if( int_ver < 64570 )
    return "7.1.1-" + buildNumber;
  if( int_ver < 69057 )
    return "7.2-" + buildNumber;
  if( int_ver < 72803 )
    return "7.2.1-" + buildNumber;
  # nb: Current version, to be replaced when a new major.minor version is released
  return "7.2.2-" + buildNumber;
}

# @brief Checks if the Synology device model is a router or not
#
# @param model the Synology device model
#
# @return TRUE if it is a Synology Router device, FALSE otherwise
#
# @note This is needed in detections that do not differentiate between DSM and SRM (mDNS, UPnP)
#
function check_is_synology_router( model ) {

  local_var model;

  if( "MR2200ac" >< model || "WRX560" >< model || model =~ "^RT" )
    return TRUE;

  return FALSE;
}
