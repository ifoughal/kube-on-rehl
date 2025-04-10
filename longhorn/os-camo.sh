#!/bin/bash

# Define the backup file path
BACKUP_FILE="/etc/os-release.bak"

# Function to apply camouflage
apply_camo() {
  # Backup the current /etc/os-release file if it doesn't already exist
  if [ ! -f $BACKUP_FILE ]; then
    sudo cp /etc/os-release $BACKUP_FILE
  fi

  # Modify /etc/os-release to reflect RHEL 9.5
  sudo bash -c 'cat > /etc/os-release <<EOF
NAME="Red Hat Enterprise Linux"
VERSION="9.5 (Ootpa)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.5"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.5 (Ootpa)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:9.5:GA"
HOME_URL="https://www.redhat.com/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"

REDHAT_BUGZILLA_PRODUCT="Red Hat Enterprise Linux 9"
REDHAT_BUGZILLA_PRODUCT_VERSION=9.5
REDHAT_SUPPORT_PRODUCT="Red Hat Enterprise Linux"
REDHAT_SUPPORT_PRODUCT_VERSION="9.5"
EOF'

  echo "The /etc/os-release file has been modified to reflect RHEL 9.5"
}

# Function to revert to the original state
revert_camo() {
  # Check if the backup file exists
  if [ -f $BACKUP_FILE ]; then
    sudo cp $BACKUP_FILE /etc/os-release
    echo "The /etc/os-release file has been reverted to its original state"
  else
    echo "Backup file not found. Cannot revert to the original state."
    exit 1
  fi
}

# Check the argument passed to the script
if [ "$1" == "camo" ]; then
  apply_camo
elif [ "$1" == "revert" ]; then
  revert_camo
else
  echo "Usage: $0 {camo|revert}"
  exit 1
fi

